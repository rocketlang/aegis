// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// @rule:KOS-050 TLS-terminating proxy — port 4856, per-boot self-signed CA, inspect before forward
// @rule:KOS-051 zero-agent-code-change — ANTHROPIC_BASE_URL / OPENAI_BASE_URL override in runner.ts
// @rule:KOS-055 HITL HTTPS flow — escalation blocks request, polls DB, forwards on ALLOW

import { existsSync, readFileSync, writeFileSync } from "fs";
import { spawnSync } from "child_process";
import { randomBytes } from "crypto";
import { checkRequestBody, checkResponseBody } from "./firewall";
import { createKavachApproval, getKavachApproval, decideKavachApproval } from "../core/db";
import { loadConfig, getAegisDir } from "../core/config";
import { join } from "path";

export interface ProxyConfig {
  port: number;
  upstream: string;       // e.g. https://api.anthropic.com
  domain: string;         // trust domain (for firewall context)
  sessionId?: string;     // KAVACHOS_SESSION_ID from runner.ts
  verbose?: boolean;
}

const CERT_PATH = "/tmp/kavachos-proxy.crt";
const KEY_PATH  = "/tmp/kavachos-proxy.key";

// @rule:KOS-050 per-boot self-signed cert — regenerated on each proxy start
function generateSelfSignedCert(): { cert: string; key: string } {
  // Reuse within the same boot (same PID tree), regen if files are stale/missing
  if (!existsSync(CERT_PATH) || !existsSync(KEY_PATH)) {
    const result = spawnSync("openssl", [
      "req", "-x509", "-newkey", "rsa:2048",
      "-keyout", KEY_PATH, "-out", CERT_PATH,
      "-days", "1", "-nodes",
      "-subj", "/CN=kavachos-proxy/O=KavachOS/OU=KERNEL",
    ], { encoding: "utf-8" });

    if (result.status !== 0) {
      throw new Error(`[kavachos:proxy] openssl cert gen failed: ${result.stderr?.slice(0, 200)}`);
    }

    process.stderr.write(`[kavachos:proxy] Self-signed TLS cert generated: ${CERT_PATH}\n`);
  }

  return {
    cert: readFileSync(CERT_PATH, "utf-8"),
    key:  readFileSync(KEY_PATH,  "utf-8"),
  };
}

// @rule:KOS-055 poll aegis.db until human decides or timeout
// Returns true=ALLOW, false=DENY/TIMEOUT. Blocks the caller (proxy request handler).
async function waitForApproval(approvalId: string, timeoutMs = 600_000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    const rec = getKavachApproval(approvalId);
    if (rec?.status === "allowed")                            return true;
    if (rec?.status === "stopped" || rec?.status === "timed_out") return false;
    await new Promise((r) => setTimeout(r, 2_000));
  }

  // Timed out — mark in DB and deny
  decideKavachApproval(approvalId, "TIMEOUT", "kavachos-proxy");
  return false;
}

// Send escalation notification via AnkrClaw (best-effort, non-blocking)
async function sendEscalationNotification(
  cfg: ReturnType<typeof loadConfig>,
  approvalId: string,
  rule: string,
  detail: string,
  domain: string,
  sessionId: string,
): Promise<void> {
  const kc = (cfg as any).kavach ?? {};
  const url: string = kc.webhook_url ?? kc.ankrclaw_url ?? "";
  if (!url) return;

  const channel = kc.notify_channel ?? "telegram";
  const to: string = channel === "telegram"
    ? (kc.notify_telegram_chat_id ?? "")
    : (kc.notify_phone ?? "");
  if (!to) return;

  const message = [
    "🔴 KavachOS L7 Proxy — SQL Escalation (Action Required)",
    "",
    `Session: ${sessionId}  |  Domain: ${domain}`,
    `Rule: ${rule}`,
    "",
    "What was detected:",
    detail,
    "",
    "The request has been paused. Reply within 10 minutes:",
    `  ALLOW ${approvalId} — forward the request`,
    `  STOP ${approvalId}  — deny, return 403 to agent`,
    "",
    "Silence = STOP (KOS-026).",
  ].join("\n");

  try {
    await fetch(`${url.replace(/\/$/, "")}/api/notify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ to, message, service: "KAVACHOS-PROXY", channel, approval_id: approvalId }),
    });
  } catch {
    // Notification failure is not fatal — DB poll is authoritative
  }
}

// Forward a request to the real upstream.
// body is the pre-read request body (as string) — we've already consumed req.body.
async function forwardToUpstream(
  req: Request,
  body: string,
  upstream: string,
): Promise<Response> {
  const url = new URL(req.url);
  const upstreamUrl = upstream.replace(/\/$/, "") + url.pathname + url.search;

  const headers = new Headers(req.headers);
  // Replace the Host header — critical for the upstream API to accept the request
  headers.set("host", new URL(upstream).host);
  // Strip proxy-internal headers
  headers.delete("x-kavachos-session");

  return fetch(upstreamUrl, {
    method: req.method,
    headers,
    body: req.method !== "GET" && req.method !== "HEAD" ? body : undefined,
  });
}

// @rule:KOS-050 main proxy entry point
export async function startProxy(config: ProxyConfig): Promise<void> {
  const { cert, key } = generateSelfSignedCert();
  const aegisCfg = loadConfig();

  process.stderr.write(
    `[kavachos:proxy] KavachOS L7 Proxy starting\n` +
    `[kavachos:proxy] Port    : ${config.port}\n` +
    `[kavachos:proxy] Upstream: ${config.upstream}\n` +
    `[kavachos:proxy] Domain  : ${config.domain}\n` +
    `[kavachos:proxy] TLS     : self-signed (${CERT_PATH})\n` +
    `[kavachos:proxy] Session : ${config.sessionId ?? "unset"}\n`
  );

  Bun.serve({
    port: config.port,
    tls: { cert, key },

    async fetch(req: Request): Promise<Response> {
      const url = new URL(req.url);

      // ── Internal proxy endpoints ─────────────────────────────────────────

      if (url.pathname === "/proxy/health") {
        return Response.json({ ok: true, upstream: config.upstream, session: config.sessionId ?? null });
      }

      // @rule:KOS-055 agent polls this to learn its request was approved/denied
      if (url.pathname.startsWith("/proxy/decision/")) {
        const id = url.pathname.slice("/proxy/decision/".length);
        const rec = getKavachApproval(id);
        if (!rec) return Response.json({ error: "not_found" }, { status: 404 });
        return Response.json({ id, status: rec.status, decided_at: rec.decided_at });
      }

      // ── Read request body (consumed once, passed everywhere) ─────────────

      const bodyText = (req.method !== "GET" && req.method !== "HEAD")
        ? await req.text()
        : "";

      // ── Request firewall (SQL + PII + BCC) ──────────────────────────────

      const reqVerdict = checkRequestBody(bodyText, config.domain);

      if (config.verbose && reqVerdict.action !== "ALLOW") {
        process.stderr.write(
          `[kavachos:proxy] ${reqVerdict.action} ${reqVerdict.rule} — ${reqVerdict.detail}\n`
        );
      }

      if (reqVerdict.action === "DENY") {
        return Response.json({
          error: "kavachos_denied",
          rule: reqVerdict.rule,
          detail: reqVerdict.detail,
          kavachos: "L7-proxy@KOS-053/KOS-056",
        }, { status: 403 });
      }

      if (reqVerdict.action === "ESCALATE") {
        // @rule:KOS-055 HITL — create approval, notify, block until decided
        const approvalId = "KOS-" + randomBytes(6).toString("hex").toUpperCase();
        const sessionId = config.sessionId ?? "proxy";

        createKavachApproval({
          id: approvalId,
          created_at: new Date().toISOString(),
          command: bodyText.slice(0, 512),
          tool_name: "L7-Proxy",
          level: 2,
          consequence: reqVerdict.detail,
          session_id: sessionId,
          timeout_ms: 600_000,
        });

        // Non-blocking notification send, but await for completeness
        sendEscalationNotification(aegisCfg, approvalId, reqVerdict.rule, reqVerdict.detail, config.domain, sessionId).catch(() => {});

        process.stderr.write(
          `[kavachos:proxy] ESCALATE ${approvalId} — rule=${reqVerdict.rule} blocking until human decides\n`
        );

        const allowed = await waitForApproval(approvalId);

        if (!allowed) {
          return Response.json({
            error: "kavachos_escalation_denied",
            escalation_id: approvalId,
            rule: reqVerdict.rule,
            kavachos: "L7-proxy@KOS-055",
          }, { status: 403 });
        }

        process.stderr.write(`[kavachos:proxy] ESCALATE ${approvalId} ALLOWED — forwarding\n`);
        // Fall through to forward
      }

      // ── Forward to real upstream ─────────────────────────────────────────

      let upstreamResp: Response;
      try {
        upstreamResp = await forwardToUpstream(req, bodyText, config.upstream);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        process.stderr.write(`[kavachos:proxy] upstream error: ${msg}\n`);
        return Response.json({ error: "upstream_unreachable", detail: msg }, { status: 502 });
      }

      // ── Response firewall (EchoLeak) ─────────────────────────────────────

      const responseText = await upstreamResp.text();
      const respVerdict = checkResponseBody(responseText, config.upstream);

      if (respVerdict.action === "REDACT") {
        process.stderr.write(
          `[kavachos:proxy] REDACT response — ${respVerdict.detail}\n`
        );
      }

      const finalBody = respVerdict.action === "REDACT" ? respVerdict.redacted! : responseText;

      // Preserve upstream headers, but ensure correct Content-Length if body changed
      const respHeaders = new Headers(upstreamResp.headers);
      if (respVerdict.action === "REDACT") {
        respHeaders.set("content-length", String(Buffer.byteLength(finalBody, "utf-8")));
        respHeaders.set("x-kavachos-redacted", "KOS-054");
      }

      return new Response(finalBody, {
        status: upstreamResp.status,
        statusText: upstreamResp.statusText,
        headers: respHeaders,
      });
    },
  });

  process.stderr.write(
    `[kavachos:proxy] Ready on https://localhost:${config.port}\n` +
    `[kavachos:proxy] Agent env override: KAVACHOS_PROXY_URL=https://localhost:${config.port}\n` +
    `[kavachos:proxy] Health: GET https://localhost:${config.port}/proxy/health\n`
  );
}
