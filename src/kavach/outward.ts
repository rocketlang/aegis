// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// KAVACH — Anumati's outward-act face: one kernel, many plug-ins (spend, send, post, share…).
// Logics: proposals/aegis-anumati--logics--formal--2026-09-22.md §7 (founder ruling 2026-10-16).
//
// @rule:ANU-011 an outward act is judged as a typed proposal; a plug-in declares, the kernel does the rest
// @rule:ANU-012 no live mandate, no outward act; the session's flow mandate must judge valid
// @rule:ANU-013 ask = PERMIT pending the person, through the approval authority, for this exact act
// @rule:ANU-014 a claim marked as needing a source carries one
// @rule:ANU-015 a budget counts what was done and what was approved but not yet done
// @rule:ANU-016 the effector is handed only what this act needs, and holds the credential
// @rule:ANU-017 every outward decision is ledgered, PERMIT included
// @rule:ANU-YK-002 a new plug-in ships observe
//
// Same discipline as anumati(): permissives are pure, cite their law and source; UNKNOWN refuses
// (ANU-004); a check that throws is UNKNOWN; only enforce-stage results set the verdict. No model is
// in the path. NOT wired into any hook or CLI: that is the founder's word.

import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { createHash } from "crypto";
import { join } from "path";
import type { Verdict, PermissiveResult } from "./anumati";

const AEGIS_DIR = join(process.env.HOME || "/root", ".aegis");
export const OUTWARD_MANDATES_FILE = join(AEGIS_DIR, "outward-mandates.json");
export const OUTWARD_LEDGER = join(AEGIS_DIR, "outward.jsonl");

// ── Plug-in contract (ANU-011) ────────────────────────────────────────────────

export type Stage = "enforce" | "observe";

export interface OutwardMandate<L = Record<string, unknown>> {
  id: string;
  kind: string;
  limits: L;
  reason: string;
  granted_by: string;
  granted_at: string;
  expires_at: string; // a mandate is always bounded in time
}

export interface Claim { text: string; source_url?: string | null }

export interface OutwardPermissive<P, L> {
  id: string;
  title: string;
  law: string;
  /** PERMIT with ask:true = everything holds, but the person decides this one (ANU-013). */
  check(p: P, limits: L, env: { now: Date }): { verdict: Verdict; detail: string; source?: string; ask?: boolean };
}

export interface OutwardPlugin<P, L, H> {
  kind: string;
  law: string;
  /** Default observe (ANU-YK-002). The founder promotes a plug-in to enforce. */
  stage?: Stage;
  /** Shape checks on the mandate limits; null = malformed, which refuses. */
  parseLimits(raw: unknown): L | null;
  /** Which live mandate covers this proposal, if any. */
  pick?(p: P, mandates: OutwardMandate<L>[]): OutwardMandate<L> | null;
  permissives: OutwardPermissive<P, L>[];
  /** Claims that need a source (ANU-014). */
  claims?(p: P): Claim[];
  /** Budget key (e.g. the lane), units this act uses, and the cap and period from the limits (ANU-015). */
  budget?(p: P, limits: L): { key: string; units: number; cap: number; period_ms: number; law?: string };
  /** The whole act as the person will be shown it before approving. */
  render(p: P): string;
  /** What the effector is handed: only what this act needs (ANU-016). */
  handoff(p: P): H;
}

// ── Ledger and decision types ────────────────────────────────────────────────

export interface OutwardLedgerEntry {
  ts: string;
  event: "decided" | "approved" | "executed" | "execute-refused";
  kind: string;
  session: string | null;
  proposal_hash: string;
  mandate_id: string | null;
  verdict?: "PERMIT" | "REFUSE";
  ask?: boolean;
  /** No non-PERMIT result and no ask: the act may proceed without anyone; it counts toward budget. */
  clean?: boolean;
  stage?: Stage;
  budget_key?: string | null;
  units?: number;
  results?: PermissiveResult[];
  detail?: string;
}

export interface OutwardDecision {
  kind: string;
  verdict: "PERMIT" | "REFUSE";
  /** PERMIT that waits for the person (ANU-013). False whenever verdict is REFUSE. */
  ask: boolean;
  stage: Stage;
  results: PermissiveResult[];
  refusals: PermissiveResult[];
  observations: PermissiveResult[];
  /** The PERMIT results that asked for the person (ANU-013). */
  asked: PermissiveResult[];
  proposal_hash: string;
  /** Exactly what the person is shown; its hash is what an approval binds to. */
  shown: string;
  mandate_id: string | null;
  budget_key: string | null;
  units: number;
  evaluated_at: string;
}

export interface OutwardContext<L> {
  session_id: string | null;
  now: Date;
  /** Snapshot of granted mandates (all kinds; expired ones are filtered here). */
  mandates: OutwardMandate<L>[];
  /** Snapshot of the outward ledger, for budgets. */
  ledger: OutwardLedgerEntry[];
  /** How the session's GTP flow mandate judges (mandateForCall(session).status). */
  flowStatus: string;
  /** Why the flow is not valid, in the caller's words (shown as the refusal detail). */
  flowDetail?: string;
}

// ── Canonical bytes ──────────────────────────────────────────────────────────

export function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v && typeof v === "object") {
    const o = v as Record<string, unknown>;
    return `{${Object.keys(o).filter((k) => o[k] !== undefined).sort().map((k) => `${JSON.stringify(k)}:${canonical(o[k])}`).join(",")}}`;
  }
  return JSON.stringify(v);
}
export const proposalHash = (kind: string, p: unknown): string => createHash("sha256").update(canonical({ kind, p }), "utf8").digest("hex");

// ── The kernel decision (pure over the context) ──────────────────────────────

export function judgeOutward<P, L, H>(plugin: OutwardPlugin<P, L, H>, proposal: P, ctx: OutwardContext<unknown>): OutwardDecision {
  const stage: Stage = plugin.stage ?? "observe";
  const results: PermissiveResult[] = [];
  const push = (id: string, title: string, law: string, verdict: Verdict, detail: string, source?: string, st: Stage = stage) =>
    results.push({ id, title, law, verdict, detail, source, stage: st });
  // ANU-012 always enforces, whatever the plug-in's stage: observe softens a plug-in's own rules while
  // they collect evidence; it never means acting with no one's consent.
  const consent = (title: string, detail: string, source: string) =>
    push("ANU-012", title, "ANU-012 — no live mandate, no outward act", "UNKNOWN", detail, source, "enforce");
  const hash = proposalHash(plugin.kind, proposal);
  let shown = "";
  try { shown = `OUTWARD ${plugin.kind} · proposal ${hash}\n${plugin.render(proposal)}`; } catch { shown = `OUTWARD ${plugin.kind} · proposal ${hash}`; }
  let ask = false;
  const asked: PermissiveResult[] = [];
  let mandate: OutwardMandate<L> | null = null;
  let budgetKey: string | null = null;
  let units = 0;

  // @rule:ANU-012 — the session's own authority first.
  if (ctx.flowStatus !== "valid") {
    consent("Session flow mandate is valid", ctx.flowDetail ?? `the session's flow mandate is ${ctx.flowStatus}`, "aegis mandates");
  }

  // @rule:ANU-012 — a live mandate for this kind, with limits that parse.
  const live = ctx.mandates.filter((m) => m && m.kind === plugin.kind && Date.parse(m.expires_at) > ctx.now.getTime());
  const parsed: OutwardMandate<L>[] = [];
  for (const m of live) {
    const l = safe(() => plugin.parseLimits(m.limits));
    if (l) parsed.push({ ...m, limits: l });
  }
  try { mandate = plugin.pick ? plugin.pick(proposal, parsed) : (parsed[0] ?? null); } catch { mandate = null; }
  if (!mandate) {
    const why = live.length === 0 ? `no live ${plugin.kind} mandate` : parsed.length === 0 ? `every live ${plugin.kind} mandate is malformed` : `no live ${plugin.kind} mandate covers this proposal`;
    consent(`A live ${plugin.kind} mandate covers this act`, why, "outward-mandates.json");
  }

  if (mandate) {
    const limits = mandate.limits;
    // The plug-in's permissives (ANU-001 discipline: pure; throw = UNKNOWN).
    for (const pm of plugin.permissives) {
      try {
        const r = pm.check(proposal, limits, { now: ctx.now });
        const res: PermissiveResult = { id: pm.id, title: pm.title, law: pm.law, verdict: r.verdict, detail: r.detail, source: r.source, stage };
        results.push(res);
        if (r.verdict === "PERMIT" && r.ask) { ask = true; asked.push(res); }
      } catch (e: any) {
        push(pm.id, pm.title, pm.law, "UNKNOWN", `permissive threw: ${e?.message ?? "unknown error"}`);
      }
    }

    // @rule:ANU-014 — every marked claim carries a source.
    let claims: Claim[] = [];
    try { claims = plugin.claims?.(proposal) ?? []; } catch { push("ANU-014", "Claims carry sources", "ANU-014 / FP-018", "UNKNOWN", "claims could not be read"); }
    const bare = claims.filter((c) => !c || typeof c.source_url !== "string" || !/^https?:\/\/\S+$/.test(c.source_url));
    if (claims.length) {
      push("ANU-014", "Claims carry sources", "ANU-014 — compute, quote or null (FP-018)", bare.length ? "REFUSE" : "PERMIT",
        bare.length ? `${bare.length} claim(s) with no source: ${bare.map((c) => JSON.stringify(c?.text ?? "")).join(", ")}` : `${claims.length} claim(s), each with a source`);
    }

    // @rule:ANU-015 — budget over the period, counting approved-but-not-done.
    try {
      const b = plugin.budget?.(proposal, limits);
      if (b) {
        budgetKey = b.key;
        units = b.units;
        const used = budgetUsed(ctx.ledger, plugin.kind, b.key, ctx.now.getTime() - b.period_ms, hash);
        const over = used + b.units > b.cap;
        push("ANU-015", "Within budget for the period", "ANU-015 — done + approved-not-done count", over ? "REFUSE" : "PERMIT",
          `${b.law ? `${b.law}: ` : ""}${used} used + ${b.units} = ${used + b.units} of ${b.cap} for ${b.key}`, "outward.jsonl");
      }
    } catch {
      push("ANU-015", "Within budget for the period", "ANU-015", "UNKNOWN", "budget could not be computed", "outward.jsonl");
    }
  }

  const notPermitted = results.filter((r) => r.verdict !== "PERMIT");
  const refusals = notPermitted.filter((r) => r.stage !== "observe");
  const observations = notPermitted.filter((r) => r.stage === "observe");
  const verdict = refusals.length === 0 ? "PERMIT" : "REFUSE";
  return {
    kind: plugin.kind, verdict, ask: verdict === "PERMIT" && ask, stage, results, refusals, observations, asked,
    proposal_hash: hash, shown, mandate_id: mandate?.id ?? null, budget_key: budgetKey, units, evaluated_at: ctx.now.toISOString(),
  };
}

function safe<T>(f: () => T): T | null {
  try { return f(); } catch { return null; }
}

/** Units used for (kind, key) since `since`: executed, person-approved, or decided clean. One count per proposal. */
export function budgetUsed(ledger: OutwardLedgerEntry[], kind: string, key: string, since: number, excludeHash?: string): number {
  const seen = new Map<string, number>();
  for (const e of ledger) {
    if (e.kind !== kind || e.budget_key !== key || Date.parse(e.ts) < since || e.proposal_hash === excludeHash) continue;
    const counts = e.event === "executed" || e.event === "approved" || (e.event === "decided" && e.clean === true);
    if (counts) seen.set(e.proposal_hash, Math.max(seen.get(e.proposal_hash) ?? 0, e.units ?? 1));
  }
  let n = 0;
  for (const u of seen.values()) n += u;
  return n;
}

// ── IO: mandates and ledger ──────────────────────────────────────────────────

/** An unreadable file grants nothing (ANU-004). */
export function readOutwardMandates(path = OUTWARD_MANDATES_FILE): OutwardMandate[] {
  try {
    if (!existsSync(path)) return [];
    const v = JSON.parse(readFileSync(path, "utf8"));
    return Array.isArray(v) ? v.filter((m) => m && typeof m === "object" && typeof m.kind === "string" && typeof m.id === "string") : [];
  } catch {
    return [];
  }
}

/** For the future grant command, run by a person. Not called by any agent path. */
export function writeOutwardMandates(list: OutwardMandate[], path = OUTWARD_MANDATES_FILE): void {
  mkdirSync(AEGIS_DIR, { recursive: true });
  writeFileSync(path, JSON.stringify(list, null, 2), { mode: 0o600 });
}

export function readOutwardLedger(path = OUTWARD_LEDGER): OutwardLedgerEntry[] {
  try {
    if (!existsSync(path)) return [];
    return readFileSync(path, "utf8").split("\n").filter(Boolean).flatMap((l) => {
      try { return [JSON.parse(l) as OutwardLedgerEntry]; } catch { return []; }
    });
  } catch {
    return [];
  }
}

/** @rule:ANU-017 every decision is ledgered, PERMIT included. A ledger that cannot be written never changes a decision. */
export function ledgerOutward(e: OutwardLedgerEntry, path = OUTWARD_LEDGER): void {
  try {
    mkdirSync(AEGIS_DIR, { recursive: true });
    appendFileSync(path, JSON.stringify(e) + "\n", { mode: 0o600 });
  } catch { /* recorded nowhere; the decision stands */ }
}

export function decidedEntry(d: OutwardDecision, session: string | null): OutwardLedgerEntry {
  return {
    ts: d.evaluated_at, event: "decided", kind: d.kind, session, proposal_hash: d.proposal_hash, mandate_id: d.mandate_id,
    verdict: d.verdict, ask: d.ask, clean: d.verdict === "PERMIT" && !d.ask && d.observations.length === 0,
    stage: d.stage, budget_key: d.budget_key, units: d.units, results: d.results,
  };
}

// ── Ask and execute (ANU-013, ANU-016) ───────────────────────────────────────

/** The approval authority, as a seam: aegis's own (approval-authority.ts) in use, a fake in tests. */
export interface Approvals {
  record(shown: string, rule: string): Promise<string>;
  consume(shown: string): Promise<boolean>;
}

export async function aegisApprovals(): Promise<Approvals> {
  const a = await import("./approval-authority");
  return {
    record: (shown, rule) => a.recordPendingAuthority(shown, rule, null),
    consume: (shown) => a.consumeApprovalAuthority(shown, null),
  };
}

export interface Effector<H> { name: string; deliver(h: H): Promise<{ ref: string }> }

export type ExecuteResult =
  | { done: true; ref: string }
  | { done: false; reason: string; approval_code?: string };

export type Preflight<H> = { ok: true; ask: boolean; handoff: H } | { ok: false; reason: string };

/**
 * Everything before the person and the effector, synchronous: the proposal is the one judged, the
 * judgement permitted it, a judgement AGAIN on fresh state still permits it, and the hand-off builds.
 */
export function preflightOutward<P, L, H>(plugin: OutwardPlugin<P, L, H>, proposal: P, d: OutwardDecision, fresh: () => OutwardContext<unknown>): Preflight<H> {
  if (proposalHash(plugin.kind, proposal) !== d.proposal_hash) return { ok: false, reason: "ANU-013: the proposal changed after it was judged" };
  if (d.verdict !== "PERMIT") return { ok: false, reason: d.refusals.map((r) => r.detail).join("; ") };
  let again: OutwardDecision;
  try { again = judgeOutward(plugin, proposal, fresh()); } catch { return { ok: false, reason: "ANU-012: the act could not be judged again before hand-off" }; }
  if (again.verdict !== "PERMIT") return { ok: false, reason: again.refusals.map((r) => r.detail).join("; ") };
  try { return { ok: true, ask: d.ask || again.ask, handoff: plugin.handoff(proposal) }; }
  catch (e: any) { return { ok: false, reason: e?.message ? String(e.message) : "ANU-016: hand-off could not be built" }; }
}

/**
 * Hand a judged act to its effector. The act is judged AGAIN first, on fresh state (`fresh`): a
 * mandate revoked, a flow ended or a budget spent since the first judgement stops it here. A REFUSE
 * never reaches the effector. An ask reaches it only once the person's approval of this exact shown
 * text is consumed; otherwise the code is returned for the person. In observe stage nothing here is
 * skipped: observe changes what refuses, never who must approve.
 */
export async function executeOutward<P, L, H>(
  plugin: OutwardPlugin<P, L, H>, proposal: P, judged: OutwardDecision, effector: Effector<H>, approvals: Approvals,
  opts: { fresh: () => OutwardContext<unknown>; session?: string | null; now?: () => Date; ledger?: (e: OutwardLedgerEntry) => void },
): Promise<ExecuteResult> {
  const d = judged;
  const now = opts.now ?? (() => new Date());
  const write = opts.ledger ?? ((e: OutwardLedgerEntry) => ledgerOutward(e));
  const base = { kind: d.kind, session: opts.session ?? null, proposal_hash: d.proposal_hash, mandate_id: d.mandate_id, budget_key: d.budget_key, units: d.units };
  const refuse = (reason: string, approval_code?: string): ExecuteResult => {
    write({ ...base, ts: now().toISOString(), event: "execute-refused", detail: reason });
    return { done: false, reason, approval_code };
  };

  const pre = preflightOutward(plugin, proposal, d, opts.fresh);
  if (!pre.ok) return refuse(pre.reason);
  if (pre.ask) {
    let ok = false;
    try { ok = await approvals.consume(d.shown); } catch { ok = false; } // an unreachable authority refuses (FP-010)
    if (!ok) {
      let code: string | undefined;
      try { code = await approvals.record(d.shown, "ANU-013"); } catch { code = undefined; }
      return refuse("ANU-013: waits for the person's approval of this exact act", code);
    }
    write({ ...base, ts: now().toISOString(), event: "approved" });
  }
  let ref: string;
  try { ({ ref } = await effector.deliver(pre.handoff)); } catch (e: any) { return refuse(`effector ${effector.name} failed: ${e?.message ?? "unknown"}`); }
  write({ ...base, ts: now().toISOString(), event: "executed", detail: `${effector.name} ref ${ref}` });
  return { done: true, ref };
}
