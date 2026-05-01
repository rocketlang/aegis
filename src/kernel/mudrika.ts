// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// Mudrika — per-agent SPIFFE-compatible identity credential
// Sanskrit: mudrika = signet ring (the proof an agent carries)
//
// @rule:KOS-060 mudrika URI = spiffe://kavachos/{domain}/{agent_id}/{session_id}
// @rule:KOS-061 55-min TTL, auto-rotate when < 5 min remain
// @rule:KOS-062 every hook validates mudrika before tool call executes; no valid mudrika = deny
//
// OQ-006 CLOSED (2026-04-30): full SPIFFE/SPIRE deferred until first external enterprise
// design partner requires it. mudrika-as-SVID is the production path until then.
// When SPIRE is adopted: trust_domain stays "kavachos", only issuance changes. (KOS-YK-003)

import { createHmac, randomBytes, timingSafeEqual } from "crypto";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "fs";
import { join } from "path";
import { getAegisDir } from "../core/config";

const TTL_MS = 55 * 60 * 1000;        // 55-min — matches SPIFFE convention
const ROTATE_EARLY_MS = 5 * 60 * 1000; // reissue when 5 min remain

export interface MudrikaCredential {
  uri: string;          // spiffe://kavachos/{domain}/{agent_id}/{session_id}
  agent_id: string;
  session_id: string;
  domain: string;
  issued_at: number;    // unix ms
  expires_at: number;   // issued_at + TTL_MS
  token: string;        // HMAC-SHA256 signed compact token
  pramana_version: "1.1";
  rule_ref: "KOS-060";
}

// ── Secret management ────────────────────────────────────────────────────────

function getSecret(): Buffer {
  const env = process.env.KAVACHOS_MUDRIKA_SECRET;
  if (env) return Buffer.from(env, "utf-8");

  // Persistent per-machine secret — generated once, mode 600
  const secretPath = join(getAegisDir(), "mudrika.secret");
  if (existsSync(secretPath)) {
    return Buffer.from(readFileSync(secretPath, "utf-8").trim(), "hex");
  }
  const secret = randomBytes(32);
  const dir = getAegisDir();
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  writeFileSync(secretPath, secret.toString("hex"), { mode: 0o600 });
  return secret;
}

// ── Token construction ───────────────────────────────────────────────────────

function payloadString(
  uri: string, agentId: string, sessionId: string,
  domain: string, issuedAt: number, expiresAt: number
): string {
  return `${uri}|${agentId}|${sessionId}|${domain}|${issuedAt}|${expiresAt}`;
}

function sign(payload: string): string {
  return createHmac("sha256", getSecret()).update(payload).digest("base64url");
}

function buildToken(
  uri: string, agentId: string, sessionId: string,
  domain: string, issuedAt: number, expiresAt: number
): string {
  const payload = payloadString(uri, agentId, sessionId, domain, issuedAt, expiresAt);
  return `${Buffer.from(payload).toString("base64url")}.${sign(payload)}`;
}

// ── Storage helpers ──────────────────────────────────────────────────────────

function agentsDir(): string {
  const dir = join(getAegisDir(), "agents");
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  return dir;
}

function mudrikaPath(agentId: string): string {
  return join(agentsDir(), `${agentId}.mudrika.json`);
}

// ── Public API ───────────────────────────────────────────────────────────────

// @rule:KOS-060 issue a SPIFFE-compatible mudrika credential at agent spawn
export function issueMudrika(
  agentId: string,
  sessionId: string,
  domain: string = "general"
): MudrikaCredential {
  const issuedAt = Date.now();
  const expiresAt = issuedAt + TTL_MS;
  const uri = `spiffe://kavachos/${domain}/${agentId}/${sessionId}`;
  const token = buildToken(uri, agentId, sessionId, domain, issuedAt, expiresAt);

  const cred: MudrikaCredential = {
    uri, agent_id: agentId, session_id: sessionId, domain,
    issued_at: issuedAt, expires_at: expiresAt,
    token, pramana_version: "1.1", rule_ref: "KOS-060",
  };

  writeFileSync(mudrikaPath(agentId), JSON.stringify(cred, null, 2), { mode: 0o600 });
  return cred;
}

// @rule:KOS-062 validate a compact token — timing-safe signature check + expiry
export function validateMudrika(
  token: string
): { valid: boolean; reason?: string; cred?: MudrikaCredential } {
  try {
    const dot = token.lastIndexOf(".");
    if (dot < 0) return { valid: false, reason: "malformed: no separator" };

    const payloadB64 = token.slice(0, dot);
    const sig = token.slice(dot + 1);
    const payload = Buffer.from(payloadB64, "base64url").toString("utf-8");

    const expectedSig = sign(payload);
    if (!timingSafeEqual(Buffer.from(sig), Buffer.from(expectedSig))) {
      return { valid: false, reason: "signature invalid" };
    }

    const parts = payload.split("|");
    if (parts.length !== 6) return { valid: false, reason: "malformed payload" };

    const [uri, agent_id, session_id, domain, issuedAtStr, expiresAtStr] = parts;
    const expiresAt = parseInt(expiresAtStr, 10);
    if (Date.now() > expiresAt) return { valid: false, reason: "expired" };

    return {
      valid: true,
      cred: {
        uri, agent_id, session_id, domain,
        issued_at: parseInt(issuedAtStr, 10),
        expires_at: expiresAt,
        token, pramana_version: "1.1", rule_ref: "KOS-060",
      },
    };
  } catch {
    return { valid: false, reason: "parse error" };
  }
}

// @rule:KOS-061 load stored credential; auto-rotate when < 5 min remain
export function loadOrRotateMudrika(agentId: string): MudrikaCredential | null {
  const path = mudrikaPath(agentId);
  if (!existsSync(path)) return null;

  try {
    const cred = JSON.parse(readFileSync(path, "utf-8")) as MudrikaCredential;
    if (Date.now() >= cred.expires_at - ROTATE_EARLY_MS) {
      return issueMudrika(cred.agent_id, cred.session_id, cred.domain);
    }
    return cred;
  } catch {
    return null;
  }
}

// @rule:KOS-062 check validity from disk — used by hooks
export function checkMudrikaValid(agentId: string): { valid: boolean; reason?: string } {
  const cred = loadOrRotateMudrika(agentId);
  if (!cred) return { valid: false, reason: "no mudrika — agent not registered" };
  return validateMudrika(cred.token);
}

// Remaining TTL in ms — used for dashboard display
export function mudrikaTtlMs(agentId: string): number {
  const cred = loadOrRotateMudrika(agentId);
  if (!cred) return 0;
  return Math.max(0, cred.expires_at - Date.now());
}
