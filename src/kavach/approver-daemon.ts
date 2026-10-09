// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.

// The separate-uid approver daemon (KAV-098 hardened mode) — the "clerk" that owns the
// destructive-gate one-time approvals under its OWN uid, so the agent's uid cannot forge one
// (review finding "point 1", Oct 2026).
//
// It runs as a dedicated account (e.g. `aegis-approver`) whose HOME/AEGIS_DIR holds the store,
// unreadable and unwritable to the agent. It listens on two unix sockets:
//
//   consume socket  — ops: pending, consume, list. Reachable by the agent's uid (ask only).
//   approve socket  — ops: approve, list. Permissioned to the approver group; the agent's uid
//                     is not in it, so it cannot open this socket.
//
// Defence in depth: even if socket permissions were wrong, this daemon REFUSES `approve` that
// arrives on the consume socket. Approving is the one power the agent must never reach.
//
// The store logic is the same pure functions the single-uid path uses (destructive-approval.ts),
// operating on the daemon's own AEGIS_DIR — one implementation, two deployments.

import { createServer, type Server, type Socket } from "net";
import { chmodSync, existsSync, mkdirSync, unlinkSync } from "fs";
import { dirname } from "path";
import { recordPending, listPending, approvePending, consumeApproval } from "./destructive-approval";
import type { ApproverOp, ApproverRequest, ApproverResponse } from "./approver-client";
import { LedgerAuthority } from "../core/ledger-authority";

export interface DaemonOptions {
  consumeSocketPath: string;
  approveSocketPath: string;
  /** The store directory this daemon owns; exported as AEGIS_DIR for the store functions. */
  storeDir: string;
  /** Off-box witness for the signed refusal ledger. Absent = signed and chained here only. */
  witnessUrl?: string;
  /** The name this ledger is known by at the witness. */
  ledgerSource?: string;
  ledgerHeartbeatMs?: number;
  /** Also write the ledger public key here, for a verifier outside the store. */
  ledgerPublicKeyOut?: string;
  /** Called with human-readable lines for audit/logging. Defaults to stderr. */
  log?: (line: string) => void;
}

// A gate may ASK for a refusal to be recorded; the number, the time and the signature are ours.
// "anchor" hands out the authority's signed statement of its own tail; submitting it to a public log is
// the asker's business (the authority needs no network and holds no log token).
const CONSUME_OPS = new Set<ApproverOp>(["pending", "consume", "list", "refusal", "ledger-status", "anchor"]);
const APPROVE_OPS = new Set<ApproverOp>(["approve", "list"]);

function handle(req: ApproverRequest, ledger: LedgerAuthority): ApproverResponse {
  try {
    switch (req.op) {
      case "pending":
        if (typeof req.command !== "string") return { ok: false, error: "pending needs a command" };
        return { ok: true, value: recordPending(req.command, String(req.rule ?? "")) };
      case "consume":
        if (typeof req.command !== "string") return { ok: false, error: "consume needs a command" };
        return { ok: true, value: consumeApproval(req.command) };
      case "list":
        return { ok: true, value: listPending() };
      case "refusal": {
        if (typeof req.gate !== "string" || !req.gate) return { ok: false, error: "refusal needs a gate" };
        const row = ledger.record(req);
        return { ok: true, value: { seq: row.seq } };
      }
      case "ledger-status":
        return { ok: true, value: ledger.status() };
      case "anchor":
        return { ok: true, value: ledger.anchor() };
      case "approve":
        if (typeof req.code !== "string") return { ok: false, error: "approve needs a code" };
        return { ok: true, value: approvePending(req.code) };
      default:
        return { ok: false, error: `unknown op '${String((req as { op?: unknown }).op)}'` };
    }
  } catch (e) {
    return { ok: false, error: (e as Error).message };
  }
}

function serve(path: string, allowed: Set<ApproverOp>, ledger: LedgerAuthority, log: (s: string) => void): Server {
  if (existsSync(path)) { try { unlinkSync(path); } catch { /* stale socket */ } }
  const dir = dirname(path);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });

  const server = createServer((sock: Socket) => {
    sock.setEncoding("utf8");
    let buf = "";
    sock.on("data", (d) => {
      buf += d;
      const nl = buf.indexOf("\n");
      if (nl === -1) return;
      let reply: ApproverResponse;
      try {
        const req = JSON.parse(buf.slice(0, nl)) as ApproverRequest;
        if (!allowed.has(req.op)) {
          // The agent reaching for `approve` on the consume socket is exactly the attack.
          log(`REFUSED op '${req.op}' on ${allowed.has("approve") ? "approve" : "consume"} socket`);
          reply = { ok: false, error: `op '${req.op}' is not allowed on this socket` };
        } else {
          reply = handle(req, ledger);
          log(`${req.op} → ${reply.ok ? "ok" : "error:" + reply.error}`);
        }
      } catch {
        reply = { ok: false, error: "malformed request" };
      }
      sock.write(JSON.stringify(reply) + "\n");
      sock.end();
    });
    sock.on("error", () => { /* client vanished */ });
  });
  server.listen(path, () => { try { chmodSync(path, 0o660); } catch { /* perms set by provisioning */ } });
  return server;
}

/** Start the daemon. Returns a stop() that unlinks both sockets. */
export function startApproverDaemon(opts: DaemonOptions): { stop: () => void; ledger: LedgerAuthority } {
  const log = opts.log ?? ((s: string) => process.stderr.write(`[aegis-approver] ${s}\n`));
  // The store must be ours and ours alone. 0o700: the agent's uid cannot read or write it.
  if (!existsSync(opts.storeDir)) mkdirSync(opts.storeDir, { recursive: true, mode: 0o700 });
  process.env.AEGIS_DIR = opts.storeDir;

  const ledger = new LedgerAuthority({
    storeDir: opts.storeDir, witnessUrl: opts.witnessUrl, source: opts.ledgerSource,
    heartbeatMs: opts.ledgerHeartbeatMs, publicKeyOut: opts.ledgerPublicKeyOut, log,
  });
  ledger.start();

  const consumeServer = serve(opts.consumeSocketPath, CONSUME_OPS, ledger, log);
  const approveServer = serve(opts.approveSocketPath, APPROVE_OPS, ledger, log);
  log(`listening — consume=${opts.consumeSocketPath} approve=${opts.approveSocketPath} store=${opts.storeDir}`);

  const stop = () => {
    ledger.stop();
    for (const s of [consumeServer, approveServer]) { try { s.close(); } catch { /* */ } }
    for (const p of [opts.consumeSocketPath, opts.approveSocketPath]) {
      if (existsSync(p)) { try { unlinkSync(p); } catch { /* */ } }
    }
    log("stopped");
  };
  return { stop, ledger };
}
