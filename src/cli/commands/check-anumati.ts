// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// PreToolUse hook face for the Anumati permissive layer.
// exit 0 = the plant may obey · exit 2 = refused
//
// @rule:ANU-003 one REFUSE refuses · @rule:ANU-004 UNKNOWN state refuses
// @rule:ANU-YK-001 shadow mode reports and never blocks — but always ledgers
//
// NOT wired into ~/.claude/settings.json. Three sessions share this tree; adding a
// hard-blocking hook to the shared config is a founder ruling, not an engineering
// convenience. See §5 of aegis-anumati--logics--formal--2026-09-22.md.

import { readFileSync, existsSync, appendFileSync } from "fs";
import { join } from "path";
import {
  anumati,
  anumatiMode,
  ledgerAnumati,
  renderRefusal,
  type ProposedAction,
} from "../../kavach/anumati";

function readStdin(): string {
  try {
    return readFileSync("/dev/stdin", "utf-8");
  } catch {
    return "";
  }
}

export default async function checkAnumati(_args: string[]): Promise<void> {
  const mode = anumatiMode();

  const stdin = readStdin().trim();
  // Empty or unparseable stdin is not a tool call and not plant state — nothing to permit.
  if (!stdin) process.exit(0);

  let payload: {
    tool_name?: string;
    session_id?: string;
    cwd?: string;
    tool_input?: Record<string, unknown>;
  };
  try {
    payload = JSON.parse(stdin);
  } catch {
    process.exit(0);
  }

  // AF-T-602 diagnostic (TEMPORARY, off unless ~/.aegis/mudrika-diag.on exists): capture what
  // the REAL PreToolUse payload carries — session_id? transcript_path? — the stable session key
  // the Mudrika-issuance fix needs. check-anumati runs on EVERY tool call (matcher ''). Never
  // affects the gate. Remove after the payload contract is known.
  try {
    if (existsSync(join(process.env.HOME || "/root", ".aegis", "mudrika-diag.on"))) {
      const p = payload as Record<string, unknown>;
      const tp = typeof p.transcript_path === "string" ? (p.transcript_path as string) : null;
      appendFileSync(join(process.env.HOME || "/root", ".aegis", "mudrika-issuance-diag.jsonl"), JSON.stringify({
        ts: new Date().toISOString(), hook: "PreToolUse:check-anumati", keys: Object.keys(p),
        tool_name: p.tool_name ?? null, session_id: p.session_id ?? null,
        transcript_path: tp, hook_event_name: p.hook_event_name ?? null,
        derivedSessionId: tp ? tp.split("/").pop()!.replace(/\.jsonl$/, "") : null,
        env_CLAUDE_SESSION_ID: process.env.CLAUDE_SESSION_ID ?? null,
      }) + "\n");
    }
  } catch { /* diagnostic must never affect the gate */ }

  const action: ProposedAction = {
    tool: payload.tool_name ?? "",
    session_id: payload.session_id || process.env.CLAUDE_SESSION_ID || "unknown",
    cwd: payload.cwd || process.cwd(),
    command: typeof payload.tool_input?.command === "string" ? (payload.tool_input.command as string) : undefined,
    file_path: typeof payload.tool_input?.file_path === "string" ? (payload.tool_input.file_path as string) : undefined,
  };

  let decision;
  try {
    decision = anumati(action);
  } catch (e: any) {
    // @rule:ANU-004 — the permissive layer failing IS unknown state. It does not wave the
    // action through. This is the opposite of the old `never block on internal errors`.
    process.stderr.write(
      `\n[ANUMATI] permissive layer failed to evaluate: ${e?.message ?? "unknown error"}\n` +
        `[ANUMATI] Unknown state refuses (ANU-004).${mode === "shadow" ? " shadow mode — not blocking.\n" : "\n"}`,
    );
    process.exit(mode === "enforce" ? 2 : 0);
  }

  // Ledger first, so an observe-stage would-refuse is recorded even when the action is
  // permitted — the shadow evidence a staged invariant is promoted (or dropped) on.
  ledgerAnumati(action, decision, mode);

  if (decision.verdict === "PERMIT") {
    // A staged (observe) invariant may have flagged this without blocking it. Say so — loudly,
    // per ANU-YK-001 — but never block. This is how ANU-I-006 runs in shadow while the
    // enforced invariants keep biting.
    for (const o of decision.observations) {
      process.stderr.write(
        `[ANUMATI] observe (${o.id}, shadow): WOULD ${o.verdict === "UNKNOWN" ? "REFUSE (unknown)" : "REFUSE"} — ${o.detail}\n`,
      );
    }
    process.exit(0);
  }

  process.stderr.write(renderRefusal(decision, mode));
  process.exit(mode === "enforce" ? 2 : 0);
}
