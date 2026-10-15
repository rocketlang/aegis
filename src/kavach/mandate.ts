// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// Mandate — the root of authority of a flow (governed-turn-protocol spec §19, P3).
//
// @rule:GTP-017 a flow has exactly one root of authority: a mandate issued by a principal
// @rule:GTP-019 the ceiling of a turn is computed from the mandate down, never declared
// @rule:GTP-022 revoking a mandate ends every flow that names it
//
// Founder rulings 2026-10-15: the principal is the first owner in the approvers file; a mandate lives
// 24 hours and is issued again at a session start when the last one is missing or no longer valid;
// refusals follow the box's enforcement mode (monitor = recorded, enforce = refused).
// Founder ruling 2026-10-15 (before 2.21.0): refusing is a separate opt-in, `kavach.mandate: "enforce"`,
// on top of `enforcement.mode: "enforce"`, so an upgrade never starts refusing a box that never set up
// an approvers file. Without it every mandate is still issued, judged and recorded.
//
// The record has the field names of a hanumang Mudrika (@xshieldai/hanumang-mandate). It is signed with
// this machine's Mudrika secret over its own fields, stored owner-only under <aegis dir>/mandates/,
// and judged by the same rule as @xshieldai/flow's mandateStatus (mirrored here until aegis depends on it).
//
// Revocation is a person's act: `aegis mandate revoke <id>` appends to mandates/revoked.jsonl. A tool
// call cannot write there (the shield guards <aegis dir>), so an agent cannot un-revoke itself.

import { appendFileSync, existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "fs";
import { randomBytes, timingSafeEqual } from "crypto";
import { join } from "path";
import { getAegisDir } from "../core/config";
import { signWithMachineSecret } from "../kernel/mudrika";

export const MANDATE_TTL_SECONDS = 24 * 60 * 60;

/**
 * What a flow must show before it closes as done (GTP-025, P5). Judged at the end of a turn by
 * `aegis flow-close` against the receipts grade of the agent's last message (no command is run):
 *   none-declared    nothing is required; the flow closes and the receipt says so
 *   receipts         no claim is FALSE or STALE, and no bare "done" that names nothing checkable
 *   receipts-strict  as receipts, and every checkable claim is PROVEN (none left with no receipt)
 */
export const RETURN_PROOFS = ["none-declared", "receipts", "receipts-strict"] as const;
export type ReturnProof = (typeof RETURN_PROOFS)[number];
export const DEFAULT_RETURN_PROOF: ReturnProof = "receipts";
export const isReturnProof = (v: unknown): v is ReturnProof => typeof v === "string" && (RETURN_PROOFS as readonly string[]).includes(v);

/** True only when the box enforces and has opted in to mandate refusals (founder ruling 2026-10-15). */
export function mandateEnforced(config: { enforcement?: { mode?: string }; kavach?: { mandate?: string } }): boolean {
  return config.enforcement?.mode === "enforce" && config.kavach?.mandate === "enforce";
}

export interface Mandate {
  mudrika_version: "v1";
  mudrika_id: string;
  principal_id: string;
  agent_id: string;
  task_id: string;
  trust_mask: number;
  scope_key: string;
  issued_at: string;
  ttl_seconds: number;
  required_return_proof: string;
  revocation_url: string;
  pramana_chain: string[];
  signature?: string;
}

export type MandateStatus = "valid" | "expired" | "revoked" | "missing" | "malformed";

const SAFE_ID = /^[A-Za-z0-9_-]{1,128}$/;

function mandatesDir(create = false): string {
  const dir = join(getAegisDir(), "mandates");
  if (create && !existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
}
const revokedPath = () => join(mandatesDir(), "revoked.jsonl");

// ── principal ──────────────────────────────────────────────────────────────────────────────────────

/** The first owner in the approvers file, as `owner:<channel>:<id>`; null when there is none. */
export function principalFromApprovers(path = process.env.AOS_APPROVERS_FILE ?? "/root/.ankr/state/ankrclaw/approvers.json"): string | null {
  try {
    const j = JSON.parse(readFileSync(path, "utf8"));
    const owners = Array.isArray(j) ? j : j?.owners;
    if (Array.isArray(owners) && owners.length) return `owner:${String(owners[0]).trim()}`;
    if (owners && typeof owners === "object") {
      for (const [channel, list] of Object.entries(owners)) {
        if (Array.isArray(list) && list.length) return `owner:${channel}:${String(list[0]).trim()}`;
      }
    }
  } catch { /* no file, no principal */ }
  return null;
}

// ── signing ────────────────────────────────────────────────────────────────────────────────────────

function canonical(m: Mandate): string {
  const { signature: _s, ...rest } = m;
  return JSON.stringify(Object.keys(rest).sort().reduce((o, k) => ((o as Record<string, unknown>)[k] = (rest as Record<string, unknown>)[k], o), {}));
}

function signatureValid(m: Mandate): boolean {
  if (typeof m.signature !== "string") return false;
  const want = Buffer.from(signWithMachineSecret(canonical(m)));
  const got = Buffer.from(m.signature);
  return got.length === want.length && timingSafeEqual(got, want);
}

// ── judging (same rule as @xshieldai/flow mandateStatus) ───────────────────────────────────────────

export function revokedIds(): Set<string> {
  const out = new Set<string>();
  try {
    for (const line of readFileSync(revokedPath(), "utf8").split("\n")) {
      if (!line.trim()) continue;
      try { const r = JSON.parse(line) as { mudrika_id?: unknown }; if (typeof r.mudrika_id === "string") out.add(r.mudrika_id); } catch { /* a bad line revokes nothing */ }
    }
  } catch { /* no file: nothing revoked */ }
  return out;
}

export function judgeMandate(m: Mandate | null, now = new Date(), revoked: ReadonlySet<string> = revokedIds()): MandateStatus {
  if (!m) return "missing";
  const issued = Date.parse(m.issued_at);
  const isMask = Number.isInteger(m.trust_mask) && m.trust_mask >= 0 && m.trust_mask <= 0xffffffff;
  if (typeof m.mudrika_id !== "string" || !SAFE_ID.test(m.mudrika_id) || !isMask || !Number.isFinite(issued) ||
      !Number.isInteger(m.ttl_seconds) || m.ttl_seconds <= 0 || !signatureValid(m)) return "malformed";
  if (revoked.has(m.mudrika_id)) return "revoked";
  return now.getTime() >= issued + m.ttl_seconds * 1000 ? "expired" : "valid";
}

// ── storage ────────────────────────────────────────────────────────────────────────────────────────

const sessionPointer = (sessionId: string) => join(mandatesDir(), `session-${sessionId}`);

export function loadMandateById(id: string): Mandate | null {
  if (!SAFE_ID.test(id)) return null;
  try { return JSON.parse(readFileSync(join(mandatesDir(), `${id}.json`), "utf8")) as Mandate; } catch { return null; }
}

export function loadMandateForSession(sessionId: string): Mandate | null {
  if (!SAFE_ID.test(sessionId)) return null;
  try { return loadMandateById(readFileSync(sessionPointer(sessionId), "utf8").trim()); } catch { return null; }
}

export function issueMandate(sessionId: string, opts: { trustMask: number; scopeKey: string; principal: string; now?: Date; returnProof?: ReturnProof }): Mandate {
  if (!SAFE_ID.test(sessionId)) throw new Error("GTP-017: session id is not a safe identifier; no mandate issued");
  const m: Mandate = {
    mudrika_version: "v1",
    mudrika_id: `mdr_${(opts.now ?? new Date()).getTime().toString(36)}_${randomBytes(6).toString("hex")}`,
    principal_id: opts.principal,
    agent_id: `cc:${sessionId}`,
    task_id: sessionId,
    trust_mask: opts.trustMask >>> 0,
    scope_key: opts.scopeKey,
    issued_at: (opts.now ?? new Date()).toISOString(),
    ttl_seconds: MANDATE_TTL_SECONDS,
    required_return_proof: opts.returnProof ?? DEFAULT_RETURN_PROOF,
    revocation_url: "aegis://mandates/revoked.jsonl",
    pramana_chain: [],
  };
  m.signature = signWithMachineSecret(canonical(m));
  mandatesDir(true);
  writeFileSync(join(mandatesDir(), `${m.mudrika_id}.json`), JSON.stringify(m, null, 2), { mode: 0o600 });
  writeFileSync(sessionPointer(sessionId), m.mudrika_id, { mode: 0o600 });
  return m;
}

/** At a session start: keep a valid mandate, otherwise issue a new one. No principal, no mandate. */
export function ensureMandateForSession(sessionId: string, opts: { trustMask: number; scopeKey: string; principal?: string | null }): { mandate: Mandate | null; issued: boolean; status: MandateStatus } {
  const current = loadMandateForSession(sessionId);
  const status = judgeMandate(current);
  if (current && status === "valid") return { mandate: current, issued: false, status };
  const principal = opts.principal === undefined ? principalFromApprovers() : opts.principal;
  if (!principal) return { mandate: null, issued: false, status: "missing" };
  const m = issueMandate(sessionId, { trustMask: opts.trustMask, scopeKey: opts.scopeKey, principal });
  return { mandate: m, issued: true, status: "valid" };
}

/** A person's act (GTP-022). Appends; never edits or removes a line. */
export function revokeMandate(id: string, by: string, reason = ""): void {
  if (!SAFE_ID.test(id)) throw new Error(`not a mandate id: ${id}`);
  mandatesDir(true);
  appendFileSync(revokedPath(), JSON.stringify({ mudrika_id: id, revoked_at: new Date().toISOString(), by, reason }) + "\n", { mode: 0o600 });
}

export function listMandates(): Mandate[] {
  try {
    return readdirSync(mandatesDir()).filter((f) => /^mdr_[A-Za-z0-9_-]+\.json$/.test(f))
      .map((f) => { try { return JSON.parse(readFileSync(join(mandatesDir(), f), "utf8")) as Mandate; } catch { return null; } })
      .filter((m): m is Mandate => m !== null)
      .sort((a, b) => (a.issued_at < b.issued_at ? 1 : -1));
  } catch { return []; }
}

/** What a hook needs per call: the session's mandate id and its status. Never throws. */
export function mandateForCall(sessionId: unknown): { mandate_id?: string; status: MandateStatus; trust_mask?: number } {
  try {
    if (typeof sessionId !== "string") return { status: "missing" };
    const m = loadMandateForSession(sessionId);
    const status = judgeMandate(m);
    return m ? { mandate_id: m.mudrika_id, status, trust_mask: m.trust_mask } : { status };
  } catch {
    return { status: "missing" };
  }
}
