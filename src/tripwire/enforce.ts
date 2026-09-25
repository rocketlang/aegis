// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// Agent Tripwire — containment ENFORCEMENT bridge (AF-T-702, AFW-011, AFW-006).
//
// The ladder (containment.ts) is POLICY: evidence → stage. This module makes a stage BITE,
// under two disciplines:
//
//   1. LAYER SEPARATION (ANU-005): an Anumati refusal never touches the gate valve. So the
//      valve action comes from HERE — the tripwire face, driven by tripwire evidence — and
//      Anumati's ANU-I-009 merely refuses actions by an already-quarantined principal. Two
//      layers, two jobs; neither reaches into the other's machinery.
//
//   2. OBSERVE-FIRST (AFW-006): a new enforcement enters in observe stage. In observe mode
//      this module reports and ledgers what it WOULD do to the valve and does nothing.
//      Promotion to enforce is a human command (`aegis tripwire-mode enforce`), sealed like
//      the anumati mode switch (ANU-007). Unlike anumati, a seal mismatch resolves to the
//      SEALED value, not the stricter one: this switch arms actions AGAINST live sessions,
//      so a hand edit must never be able to conjure enforcement the human never sealed.
//
// De-escalation is human-only (AFW-011): evidence only accumulates, so the computed stage is
// monotonic — until `aegis tripwire-clear <principal> --reason` writes a clear record, after
// which only evidence NEWER than the clear counts. Revoke stays capture-gated in the ladder
// itself and maps to the LOCKED valve state, which already requires human release (KAV-066).

import { existsSync, readFileSync, writeFileSync, mkdirSync } from "fs";
import { join } from "path";
import { createHash } from "crypto";
import { containmentStage, type Stage, type StageDecision } from "./containment";

const AEGIS_DIR = join(process.env.HOME || "/root", ".aegis");
const LEDGER = join(AEGIS_DIR, "tripwire.jsonl");
const CLEARS = join(AEGIS_DIR, "tripwire-clears.json");
const MODE_FILE = join(AEGIS_DIR, "tripwire-mode");
const MODE_SEAL = join(AEGIS_DIR, "tripwire-mode.seal.json");

// ── Evidence (pure) ───────────────────────────────────────────────────────────

export interface ClearRecord {
  cleared_at: string; // ISO — only ledger entries strictly after this count
  by: string;
  reason: string;
}

/**
 * Tripwire evidence for a principal from raw ledger lines, honouring a human clear:
 * only entries strictly newer than the clear count. Containment records themselves
 * (kind:"containment") are actions we took, not tells the principal gave — excluded,
 * or every enforcement would feed the evidence that justifies more enforcement.
 */
export function parseEvidence(
  lines: string[],
  principal: string,
  clear?: ClearRecord,
): { hits: number; distinctKinds: number } {
  let hits = 0;
  const kinds = new Set<string>();
  const cutoff = clear ? Date.parse(clear.cleared_at) : -Infinity;
  for (const line of lines) {
    if (!line.trim()) continue;
    try {
      const r = JSON.parse(line);
      if (String(r.session) !== principal) continue;
      if (r.kind === "containment") continue;
      const ts = Date.parse(String(r.ts ?? ""));
      if (!Number.isFinite(ts) || ts <= cutoff) continue;
      hits++;
      if (r.kind) kinds.add(String(r.kind));
    } catch { /* unparseable line is not evidence */ }
  }
  return { hits, distinctKinds: kinds.size };
}

/** watch → nothing; throttle/quarantine/revoke → the valve transition of the same severity. */
export function stageToValveAction(stage: Stage): "throttle" | "close" | "lock" | null {
  switch (stage) {
    case "watch": return null;
    case "throttle": return "throttle";   // OPEN → THROTTLED (spawn bit cleared)
    case "quarantine": return "close";    // → CLOSED (perm mask 0, kept alive to inspect)
    case "revoke": return "lock";         // → LOCKED (human release only, KAV-066)
  }
}

// ── Mode (sealed, observe-first) ──────────────────────────────────────────────

export type TripwireMode = "observe" | "enforce";

/**
 * Sealed mode read. Default observe (AFW-006). Unlike anumati's stricter-wins, a seal
 * mismatch here resolves to the SEALED value, and no seal means observe: enforcement that
 * a human never sealed must not exist, because this switch arms actions AGAINST sessions.
 */
export function tripwireMode(): { mode: TripwireMode; note: string | null } {
  const env = process.env.TRIPWIRE_MODE;
  if (env === "observe" || env === "enforce") return { mode: env, note: "set by TRIPWIRE_MODE in this process environment" };

  let fileMode: TripwireMode | null = null;
  let fileHash: string | null = null;
  try {
    if (existsSync(MODE_FILE)) {
      const raw = readFileSync(MODE_FILE, "utf-8");
      const v = raw.trim();
      if (v === "observe" || v === "enforce") { fileMode = v; fileHash = createHash("sha256").update(raw).digest("hex"); }
    }
  } catch { /* absent */ }

  let seal: { mode?: string; sha256?: string } | null = null;
  try { if (existsSync(MODE_SEAL)) seal = JSON.parse(readFileSync(MODE_SEAL, "utf-8")); } catch { seal = null; }

  const sealedMode: TripwireMode | null = seal?.mode === "enforce" || seal?.mode === "observe" ? seal.mode : null;
  if (fileMode === null) {
    if (sealedMode) return { mode: sealedMode, note: "mode file missing — using the last sealed value" };
    return { mode: "observe", note: "no mode set — observe (AFW-006: a new enforcement enters in observe)" };
  }
  if (!seal?.sha256) return { mode: "observe", note: "mode file is UNSEALED — observe until set via `aegis tripwire-mode`" };
  if (seal.sha256 === fileHash) return { mode: fileMode, note: null };
  return {
    mode: sealedMode ?? "observe",
    note: `SEAL MISMATCH — mode file says ${fileMode}, seal says ${sealedMode ?? "nothing"}; using the sealed value (a hand edit cannot arm enforcement)`,
  };
}

/** Write value + seal together. The only sanctioned writer (never `echo enforce >`). */
export function writeTripwireMode(mode: TripwireMode): void {
  mkdirSync(AEGIS_DIR, { recursive: true });
  const raw = mode + "\n";
  writeFileSync(MODE_FILE, raw);
  writeFileSync(MODE_SEAL, JSON.stringify({ mode, sha256: createHash("sha256").update(raw).digest("hex"), set_at: new Date().toISOString() }, null, 2));
}

// ── Clears (the human de-escalation path) ─────────────────────────────────────

export function readClears(): Record<string, ClearRecord> {
  try {
    if (existsSync(CLEARS)) return JSON.parse(readFileSync(CLEARS, "utf-8"));
  } catch { /* corrupt = no clears; evidence stands */ }
  return {};
}

export function writeClear(principal: string, by: string, reason: string): void {
  const clears = readClears();
  clears[principal] = { cleared_at: new Date().toISOString(), by, reason };
  mkdirSync(AEGIS_DIR, { recursive: true });
  writeFileSync(CLEARS, JSON.stringify(clears, null, 2));
}

// ── Stage for a principal (IO wrapper over the pure pieces) ──────────────────

export function stageFor(principal: string): { decision: StageDecision; hits: number; distinctKinds: number } {
  let lines: string[] = [];
  try { if (existsSync(LEDGER)) lines = readFileSync(LEDGER, "utf-8").split("\n"); } catch { /* no ledger = no evidence */ }
  const ev = parseEvidence(lines, principal, readClears()[principal]);
  // Prior defaults to watch: evidence is monotonic between clears, so recomputation cannot
  // de-escalate by itself; a clear resets the evidence window and THAT is the human path.
  const decision = containmentStage(ev);
  return { decision, ...ev };
}

// ── Apply (observe reports, enforce bites) ────────────────────────────────────

export interface ValveActions {
  throttle(id: string, reason: string): unknown;
  close(id: string, reason: string): unknown;
  lock(id: string, reason: string, by?: string): unknown;
}

export interface ApplyResult {
  stage: Stage;
  action: "throttle" | "close" | "lock" | null;
  applied: boolean;
  detail: string;
}

/**
 * Make the stage bite (enforce) or say what it would do (observe). Valve functions are
 * injected so tests can force both outcomes without a real valve record. @rule:AFW-011
 */
export function applyContainment(
  principal: string,
  decision: StageDecision,
  mode: TripwireMode,
  valve: ValveActions,
  ledgerWrite: (rec: Record<string, unknown>) => void,
): ApplyResult {
  const action = stageToValveAction(decision.stage);
  if (!action) return { stage: decision.stage, action: null, applied: false, detail: "watch — no valve action" };

  const reason = `tripwire containment: ${decision.reason}`;
  let applied = false;
  let detail: string;
  if (mode === "enforce") {
    if (action === "throttle") valve.throttle(principal, reason);
    else if (action === "close") valve.close(principal, reason);
    else valve.lock(principal, reason, "tripwire-verified-capture");
    applied = true;
    detail = `valve ${action} applied to ${principal} (${decision.stage})`;
  } else {
    detail = `observe — WOULD ${action} valve for ${principal} (${decision.stage}); promote with: aegis tripwire-mode enforce`;
  }

  ledgerWrite({
    ts: new Date().toISOString(),
    session: principal,
    kind: "containment",
    stage: decision.stage,
    valve_action: action,
    applied,
    detail: decision.reason,
  });
  return { stage: decision.stage, action, applied, detail };
}
