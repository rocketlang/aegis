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
  if (tokens.length) {
    const c = detectCanaryTrip(JSON.stringify(payload.tool_input ?? ""), tokens);
    if (c.tripped) ledger({ kind: "canary", stage: c.stage, token: c.token, tool: payload.tool_name ?? "", detail: c.detail });
  }

  // WATCH stage: alert + ledger, never block. Escalation is evidence-gated, never on one touch.
  process.exit(0);
}
