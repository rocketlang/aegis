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
import { chmodSync, existsSync, mkdirSync, readFileSync, unlinkSync } from "fs";
import { dirname } from "path";
import { recordPending, listPending, approvePending, consumeApproval } from "./destructive-approval";
import type { ApproverOp, ApproverRequest, ApproverResponse } from "./approver-client";
import { LedgerAuthority } from "../core/ledger-authority";
import { isNonce } from "../core/ledger-sign";
import { PINNED_LEDGER_KEY_PATH } from "../core/refusal-ledger";

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
  /** The ledger authority's clock. Only a test replaces it. */
  ledgerNow?: () => Date;
  /**
   * Mode of the consume socket. Default 0o660: this account and its group. A gate running as another
   * account can ask only if it is in that group, or if this is 0o666. The approve socket is always 0o660.
   */
  consumeSocketMode?: number;
  /** Give a DATED anchor to any asker on the consume socket, as through 2.17.1. Default: approve socket only. */
  datedAnchorOnConsume?: boolean;
  /** Called with human-readable lines for audit/logging. Defaults to stderr. */
  log?: (line: string) => void;
}

// A gate may ASK for a refusal to be recorded; the number, the time and the signature are ours.
// "anchor" hands out the authority's signed statement of its own tail; submitting it to a public log is
// the asker's business (the authority needs no network and holds no log token).
const CONSUME_OPS = new Set<ApproverOp>(["pending", "consume", "list", "refusal", "ledger-status", "anchor"]);
// The approve socket is the operators' socket: a person approves there, and a DATED anchor is asked for
// there. Through 2.17.1 any asker on the consume socket could have the authority sign "on this day the
// ledger stands at row N". The statement is true, but the first dated leaf in a public log switches that
// ledger to one leaf a day for good, and a leaf needs nothing but this signature to be accepted as ours:
// whoever could ask could throw the switch. An undated anchor stays where it was.
const APPROVE_OPS = new Set<ApproverOp>(["approve", "list", "anchor", "ledger-status"]);
export const DATED_ON_APPROVE_ONLY = "a dated anchor is given on the approve socket only";

function handle(req: ApproverRequest, ledger: LedgerAuthority, on: { approveSocket: boolean; datedOnConsume: boolean }): ApproverResponse {
  try {
    switch (req.op) {
      case "pending":
        if (typeof req.command !== "string") return { ok: false, error: "pending needs a command" };
        return { ok: true, value: recordPending(req.command, String(req.rule ?? ""), Date.now(), typeof req.cwd === "string" ? req.cwd : null) };
      case "consume":
        if (typeof req.command !== "string") return { ok: false, error: "consume needs a command" };
        return { ok: true, value: consumeApproval(req.command, Date.now(), typeof req.cwd === "string" ? req.cwd : null) };
      case "list":
        return { ok: true, value: listPending() };
      case "refusal": {
        if (typeof req.gate !== "string" || !req.gate) return { ok: false, error: "refusal needs a gate" };
        const row = ledger.record(req);
        // The signed row itself, and a receipt bound to the asker's nonce: a gate with a pinned public key
        // checks both, so an answer from anything that does not hold the ledger key is not taken as signed.
        const nonce = (req as { nonce?: unknown }).nonce;
        return { ok: true, value: { seq: row.seq, row, ...(isNonce(nonce) ? { receipt: ledger.receipt(nonce, row) } : {}) } };
      }
      case "ledger-status":
        return { ok: true, value: ledger.status() };
      case "anchor":
        // "dated" is a yes or no. The day itself is the authority's own clock (core/ledger-anchor.ts, form 2).
        if (req.dated === true && !on.approveSocket && !on.datedOnConsume) {
          return { ok: false, error: `${DATED_ON_APPROVE_ONLY} (it switches this ledger to one leaf a day, for good). Ask there, or start the authority with --dated-anchor-on-consume.` };
        }
        return { ok: true, value: ledger.anchor(req.dated === true) };
      case "approve":
        if (typeof req.code !== "string") return { ok: false, error: "approve needs a code" };
        return { ok: true, value: approvePending(req.code, Date.now(), { unseen: req.unseen === true }) };
      default:
        return { ok: false, error: `unknown op '${String((req as { op?: unknown }).op)}'` };
    }
  } catch (e) {
    return { ok: false, error: (e as Error).message };
  }
}

// A request is one short line of JSON. Without a limit, bytes sent with no newline were kept for as long as the
// connection stayed open: 69 MB sent took the daemon from 55 to 125 MB (10 October 2026). Any local process
// that can reach the consume socket could grow the authority until the system killed it.
export const MAX_REQUEST_BYTES = 64 * 1024;
const idleMs = (): number => { const n = parseInt(process.env.AEGIS_APPROVER_IDLE_MS || "", 10); return Number.isFinite(n) && n > 0 ? n : 10_000; };

function serve(path: string, allowed: Set<ApproverOp>, ledger: LedgerAuthority, log: (s: string) => void, mode = 0o660, datedOnConsume = false): Server {
  if (existsSync(path)) { try { unlinkSync(path); } catch { /* stale socket */ } }
  const dir = dirname(path);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });

  const server = createServer((sock: Socket) => {
    sock.setEncoding("utf8");
    let buf = "";
    // A connection that says nothing is closed: an asker sends one line and reads one line.
    sock.setTimeout(idleMs(), () => { sock.destroy(); });
    sock.on("data", (d) => {
      buf += d;
      const nl = buf.indexOf("\n");
      if ((nl === -1 ? buf.length : nl) > MAX_REQUEST_BYTES) {
        log(`REFUSED a request larger than ${MAX_REQUEST_BYTES} bytes on the ${allowed.has("approve") ? "approve" : "consume"} socket`);
        buf = "";
        sock.write(JSON.stringify({ ok: false, error: `request too large (limit ${MAX_REQUEST_BYTES} bytes)` }) + "\n");
        sock.destroy();
        return;
      }
      if (nl === -1) return;
      let reply: ApproverResponse;
      try {
        const req = JSON.parse(buf.slice(0, nl)) as ApproverRequest;
        if (!allowed.has(req.op)) {
          // The agent reaching for `approve` on the consume socket is exactly the attack.
          log(`REFUSED op '${req.op}' on ${allowed.has("approve") ? "approve" : "consume"} socket`);
          reply = { ok: false, error: `op '${req.op}' is not allowed on this socket` };
        } else {
          reply = handle(req, ledger, { approveSocket: allowed.has("approve"), datedOnConsume });
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
  server.listen(path, () => { try { chmodSync(path, mode); } catch { /* perms set by provisioning */ } });
  return server;
}

// Nothing pinned the ledger key for the gates through 2.17.0, so an install with an authority ran with
// every answer "unchecked" and no word of it (pointed out by Andrey Lazarev, 11 October 2026). This
// account cannot write /etc, so it says what a person has to run.
export function sayPinState(publicKey: string, log: (s: string) => void, pinPath = PINNED_LEDGER_KEY_PATH): void {
  try {
    if (!existsSync(pinPath)) {
      log(`the ledger key is NOT pinned for the gates (${pinPath} does not exist): a gate cannot tell this authority's answer from anyone else's. As root: aegis ledger-pin --from <this store>/ledger-signing.pub`);
      return;
    }
    const same = (a: string, b: string) => a.replace(/\s+/g, "") === b.replace(/\s+/g, "");
    if (!same(readFileSync(pinPath, "utf-8"), publicKey)) {
      log(`THE PINNED LEDGER KEY IS NOT THIS AUTHORITY'S KEY (${pinPath}): every gate on this box will refuse this authority's answers as not signed. As root, after checking which is right: aegis ledger-pin --from <this store>/ledger-signing.pub --replace`);
    } else log(`the ledger key pinned for the gates (${pinPath}) is this authority's key`);
  } catch (e) {
    log(`could not read the pinned ledger key at ${pinPath}: ${(e as Error).message}`);
  }
}

/** Start the daemon. Returns a stop() that unlinks both sockets. */
export function startApproverDaemon(opts: DaemonOptions): { stop: () => void; ledger: LedgerAuthority } {
  const log = opts.log ?? ((s: string) => process.stderr.write(`[aegis-approver] ${s}\n`));
  // The store must be ours and ours alone. 0o700: the agent's uid cannot read or write it.
  if (!existsSync(opts.storeDir)) mkdirSync(opts.storeDir, { recursive: true, mode: 0o700 });
  process.env.AEGIS_DIR = opts.storeDir;

  const ledger = new LedgerAuthority({
    storeDir: opts.storeDir, witnessUrl: opts.witnessUrl, source: opts.ledgerSource,
    heartbeatMs: opts.ledgerHeartbeatMs, publicKeyOut: opts.ledgerPublicKeyOut, now: opts.ledgerNow, log,
  });
  ledger.start();

  const consumeMode = opts.consumeSocketMode ?? 0o660;
  const consumeServer = serve(opts.consumeSocketPath, CONSUME_OPS, ledger, log, consumeMode, opts.datedAnchorOnConsume === true);
  const approveServer = serve(opts.approveSocketPath, APPROVE_OPS, ledger, log);
  log(`listening — consume=${opts.consumeSocketPath} (mode ${consumeMode.toString(8)}) approve=${opts.approveSocketPath} (mode 660) store=${opts.storeDir}`);
  sayPinState(ledger.status().public_key, log);

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
