// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.

// Client for the separate-uid approver daemon (KAV-098 hardened mode).
//
// In the single-uid default install, the destructive gate reads and writes its one-time
// approvals in a file the agent's own uid can write — so the agent can forge an approval
// (review finding "point 1", Oct 2026). Hardened mode moves the store under a SEPARATE uid:
// a small daemon (`aegis approver-daemon`) owns the store and listens on two unix sockets.
//
//   consume socket  — the gate asks "is there a live approval for this exact command?"
//                     (ops: pending, consume, list). Reachable by the agent's uid.
//   approve socket  — a PERSON approves one pending command (ops: approve, list). Permissioned
//                     to the approver group the agent's uid is NOT in. The agent cannot open it.
//
// The agent never writes the store and never opens the approve socket; it can only ask. That
// is the uid boundary the review asked for, enforced by the OS (socket file permissions) and
// again by the daemon (it refuses `approve` arriving on the consume socket).
//
// This module is used ONLY when hardened mode is on (a consume-socket path is configured).
// Absent, the gate uses the local-file path in destructive-approval.ts, unchanged.

import { createConnection } from "net";
import type { Approval, PendingRefusal } from "./destructive-approval";

export const CONSUME_SOCK_ENV = "AEGIS_APPROVER_CONSUME_SOCKET";
export const APPROVE_SOCK_ENV = "AEGIS_APPROVER_APPROVE_SOCKET";

/** Hardened mode is on when the gate has been told where the approver's consume socket is. */
export const isHardened = (): boolean => Boolean(process.env[CONSUME_SOCK_ENV]);

// "refusal" and "ledger-status" are the signed refusal ledger (core/ledger-authority.ts): a gate asks
// the authority to record a refusal; it cannot sign one itself.
export type ApproverOp = "pending" | "consume" | "approve" | "list" | "refusal" | "ledger-status" | "anchor";
export interface ApproverRequest {
  op: ApproverOp; command?: string; rule?: string | null; code?: string;
  gate?: string; kind?: string; session?: string | null;
}
export interface ApproverResponse<T = unknown> { ok: boolean; value?: T; error?: string }

const CONNECT_TIMEOUT_MS = 3000;

// One request, one response, newline-framed JSON, then close. A tiny protocol on purpose:
// the approver does one small, auditable thing.
function ask<T>(socketPath: string, req: ApproverRequest): Promise<ApproverResponse<T>> {
  return new Promise((resolve) => {
    let buf = "";
    let settled = false;
    const done = (r: ApproverResponse<T>) => { if (!settled) { settled = true; try { sock.destroy(); } catch { /* */ } resolve(r); } };
    const sock = createConnection(socketPath);
    sock.setEncoding("utf8");
    sock.setTimeout(CONNECT_TIMEOUT_MS, () => done({ ok: false, error: "approver timeout" }));
    sock.on("error", (e) => done({ ok: false, error: `approver unreachable: ${(e as Error).message}` }));
    sock.on("connect", () => sock.write(JSON.stringify(req) + "\n"));
    sock.on("data", (d) => {
      buf += d;
      const nl = buf.indexOf("\n");
      if (nl === -1) return;
      try { done(JSON.parse(buf.slice(0, nl)) as ApproverResponse<T>); }
      catch { done({ ok: false, error: "approver sent a malformed reply" }); }
    });
    sock.on("end", () => { if (!settled) done({ ok: false, error: "approver closed without a reply" }); });
  });
}

/** Ask the ledger authority at socketPath one question (ledger-status, anchor). Never throws. */
export function askLedgerAuthority<T>(socketPath: string, op: "ledger-status" | "anchor"): Promise<ApproverResponse<T>> {
  return ask<T>(socketPath, { op });
}

const consumeSock = (): string => {
  const p = process.env[CONSUME_SOCK_ENV];
  if (!p) throw new Error("hardened mode is not configured (no consume socket)");
  return p;
};
const approveSock = (): string => process.env[APPROVE_SOCK_ENV] || consumeSock();

/**
 * Remote one-time-approval check for exactly this command, used up in the daemon's store.
 * FAIL LOUD: if the approver cannot be reached in hardened mode, this throws — the caller
 * must refuse the command, never fall back to the writable local file.
 */
export async function remoteConsume(command: string): Promise<boolean> {
  const r = await ask<boolean>(consumeSock(), { op: "consume", command });
  if (!r.ok) throw new Error(`approver consume failed: ${r.error ?? "unknown"}`);
  return r.value === true;
}

export async function remoteRecordPending(command: string, rule: string): Promise<string> {
  const r = await ask<string>(consumeSock(), { op: "pending", command, rule });
  if (!r.ok) throw new Error(`approver pending failed: ${r.error ?? "unknown"}`);
  return String(r.value ?? "");
}

export async function remoteListPending(): Promise<PendingRefusal[]> {
  const r = await ask<PendingRefusal[]>(consumeSock(), { op: "list" });
  if (!r.ok) throw new Error(`approver list failed: ${r.error ?? "unknown"}`);
  return Array.isArray(r.value) ? r.value : [];
}

/** Where the authority's signed refusal ledger stands. Null when it cannot be asked. */
export async function remoteLedgerStatus(socketPath = process.env.AEGIS_LEDGER_SOCKET || consumeSock()): Promise<Record<string, unknown> | null> {
  const r = await ask<Record<string, unknown>>(socketPath, { op: "ledger-status" });
  return r.ok && r.value ? r.value : null;
}

/** A PERSON approves one pending command over the restricted approve socket. */
export async function remoteApprove(code: string): Promise<(Approval & { shown: string; rule: string }) | null> {
  const r = await ask<(Approval & { shown: string; rule: string }) | null>(approveSock(), { op: "approve", code });
  if (!r.ok) throw new Error(`approver approve failed: ${r.error ?? "unknown"}`);
  return (r.value as (Approval & { shown: string; rule: string }) | null) ?? null;
}
