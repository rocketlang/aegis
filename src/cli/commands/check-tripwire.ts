// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// PreToolUse face for the Agent Tripwire (AGT-018). Reads a tool call from stdin; if it names
// a honeypot tool, it records a tripwire alert and announces it — but at the WATCH stage it
// NEVER blocks (exit 0). A tripwire must not kill on a guess: the first touch is evidence, not
// a verdict. (Wiring this into settings.json is a founder ruling — a new hook on the shared
// config — so this ships callable but is not auto-wired.) @rule:AGT-018

import { readFileSync, appendFileSync, mkdirSync } from "fs";
import { join } from "path";
import { tripwireVerdict } from "../../tripwire/honeypot";
import { detectCanaryTrip } from "../../tripwire/canary";
import { loadCanaries } from "./tripwire-canary";
import { stageFor, tripwireMode, applyContainment } from "../../tripwire/enforce";
import { throttleValve, closeValve, lockValve } from "../../kavach/gate-valve";

const AEGIS_DIR = join(process.env.HOME || "/root", ".aegis");
const LEDGER = join(AEGIS_DIR, "tripwire.jsonl");

function recordTripwire(rec: Record<string, unknown>): void {
  try {
    mkdirSync(AEGIS_DIR, { recursive: true });
    appendFileSync(LEDGER, JSON.stringify(rec) + "\n");
  } catch {
    // A tripwire ledger write must never itself block or crash the action.
  }
}

export default async function checkTripwire(_args: string[]): Promise<void> {
  let stdin = "";
  try { stdin = readFileSync("/dev/stdin", "utf-8").trim(); } catch { /* no stdin */ }
  if (!stdin) process.exit(0);

  let payload: { tool_name?: string; session_id?: string; agent_id?: string; cwd?: string; tool_input?: unknown };
  try { payload = JSON.parse(stdin); } catch { process.exit(0); }

  const session = payload.session_id ?? payload.agent_id ?? process.env.CLAUDE_SESSION_ID ?? "unknown";
  const ledger = (rec: Record<string, unknown>) => {
    recordTripwire({ ts: new Date().toISOString(), session, cwd: payload.cwd ?? null, ...rec });
    process.stderr.write(`[TRIPWIRE] ${String(rec.stage).toUpperCase()} — ${rec.detail}\n`);
  };

  // Honeypot tool touched?
  const v = tripwireVerdict(payload.tool_name ?? "");
  if (v.tripped) ledger({ kind: "honeypot", stage: v.stage, tool: v.tool, detail: v.detail });

  // Document canary acted on? Scan the tool input for any registered canary token (AF-T-603).
  const tokens = loadCanaries().map((c) => c.token);
  let canaryTripped = false;
  if (tokens.length) {
    const c = detectCanaryTrip(JSON.stringify(payload.tool_input ?? ""), tokens);
    if (c.tripped) { canaryTripped = true; ledger({ kind: "canary", stage: c.stage, token: c.token, tool: payload.tool_name ?? "", detail: c.detail }); }
  }

  // AF-T-702 — containment: on a fresh tell, recompute the principal's stage from ALL its
  // evidence and apply it (observe: report only; enforce: the valve bites on the principal's
  // NEXT act). This face itself still exits 0 — the tripwire never blocks the observed call;
  // narrowing lands via checkValve/ANU-I-009 downstream. Human de-escalation:
  // `aegis tripwire-clear`. @rule:AFW-011 @rule:AFW-006
  if ((v.tripped || canaryTripped) && session !== "unknown") {
    try {
      const { decision } = stageFor(session);
      const { mode } = tripwireMode();
      const r = applyContainment(session, decision, mode, { throttle: throttleValve, close: closeValve, lock: lockValve }, recordTripwire);
      if (r.action) process.stderr.write(`[TRIPWIRE] containment (${mode}): ${r.detail}\n`);
    } catch {
      // Containment failing must not crash the hook; the WATCH ledger entry above stands.
    }
  }

  // Alert + ledger always; block never (the valve, not this face, is what bites).
  process.exit(0);
}
