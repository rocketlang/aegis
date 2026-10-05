// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// AEGIS Hook — check-budget
// Called by Claude Code PreToolUse hook before every tool use.
// Default mode (alert): NEVER blocks — only warns to stderr.
// Enforce mode: blocks (exit 2) when budget is exhausted or agent soft-stop threshold hit.
//
// THIS HOOK FAILS OPEN, by design: if its own state cannot be read it exits 0, so that a
// fault in the budget store cannot stop all work. When that happens it says so on stderr.
//
// @rule:KAV-100 — the session comes from the hook's payload (hook-input.ts). The per-agent
// checks below are kept per session; until 2.6.0 they were looked up under "unknown".
//
// Phase 3: per-agent EWMA projection, 80% alert, 95% soft-stop (V2-064)
// @rule:KAV-009 Projected cost alerts
// @rule:KAV-016 L1 Soft Stop at 95% of agent cap
// @rule:INF-KAV-008 80% alert threshold

import { loadConfig, configFileProblem } from "../../core/config";
import { readHookInput } from "../hook-input";
import { getBudgetState, getAgentCostProjection, requestStop } from "../../core/db";
import { loadEnvelopeBySessionId } from "../../core/ase";

export default function checkBudget(_args: string[]): void {
  try {
    const { agentId } = readHookInput();
    const config = loadConfig();
    const enforce = config.enforcement?.mode === "enforce";
    const problem = configFileProblem();
    if (problem) process.stderr.write(`[AEGIS] ${problem} — running on the DEFAULT settings (mode: ${config.enforcement?.mode ?? "alert"})\n`);

    // --- BMOS-T-016: Expiry gate — check agent session expiry before any tool use ---
    // @rule:BMOS-008 Expiry gate: expired credential blocks all further tool calls
    {
      try {
        const envelope = loadEnvelopeBySessionId(agentId);
        if (envelope?.expires_at && envelope.expires_at !== "task_end" && envelope.expires_at !== "") {
          const expired = new Date(envelope.expires_at).getTime() < Date.now();
          if (expired) {
            const msg = `[BMOS:expiry] Session ${agentId} expired at ${envelope.expires_at} (BMOS-008)`;
            if (enforce) {
              process.stderr.write(msg + " — BLOCKED\n");
              process.exit(2);
            } else {
              process.stderr.write(msg + " — WARNING (enforce mode off)\n");
            }
          }
        }
      } catch { /* non-fatal — fail-open */ }
    }

    // --- Session-level budget check ---
    const daily = getBudgetState("daily", config.budget.daily_limit_usd);

    if (daily.percent >= 100) {
      const msg = `AEGIS: Daily budget at ${daily.percent.toFixed(0)}% ($${daily.spent_usd.toFixed(2)}/$${daily.limit_usd})`;
      if (enforce) {
        process.stderr.write(msg + " — BLOCKED. Run: aegis budget set daily <N>\n");
        process.exit(2);
      } else {
        process.stderr.write(msg + " — WARNING (enforce mode off)\n");
      }
    } else if (daily.percent >= 90) {
      process.stderr.write(`AEGIS: Daily budget at ${daily.percent.toFixed(0)}% — wrapping up soon\n`);
    }

    const weekly = getBudgetState("weekly", config.budget.weekly_limit_usd);
    if (weekly.percent >= 100) {
      if (enforce) {
        process.stderr.write(`AEGIS: Weekly budget exhausted — BLOCKED\n`);
        process.exit(2);
      }
      // In alert mode the warning is the whole product; until 2.6.0 a spent week was silent.
      process.stderr.write(`AEGIS: Weekly budget at ${weekly.percent.toFixed(0)}% ($${weekly.spent_usd.toFixed(2)}/$${weekly.limit_usd}) — WARNING (enforce mode off)\n`);
    }

    // --- V2-064: Per-agent EWMA projection ---
    // @rule:KAV-009 Projected cost, INF-KAV-008 80% alert, KAV-016 95% soft-stop
    try {
      const proj = getAgentCostProjection(agentId);
      if (proj) {
        if (proj.alert_level === "soft_stop") {
          process.stderr.write(
            `[KAVACH:budget] SOFT STOP: ${agentId} projected $${proj.projected_total_usd.toFixed(4)} = ${proj.pct_of_cap.toFixed(0)}% of $${proj.budget_cap_usd} cap — INF-KAV-008\n`
          );
          if (enforce) {
            requestStop(agentId);
            process.stderr.write(`[KAVACH:budget] stop_requested set — complete current tool call then yield.\n`);
            process.exit(2);
          }
        } else if (proj.alert_level === "warn") {
          process.stderr.write(
            `[KAVACH:budget] WARN: ${agentId} at ${proj.pct_of_cap.toFixed(0)}% of cap ($${proj.budget_used_usd.toFixed(4)}/$${proj.budget_cap_usd}) — KAV-009\n`
          );
        }
      }
    } catch { /* DB may not have this agent — non-fatal */ }

    process.exit(0);
  } catch (err) {
    // Fails OPEN (see the header). Say so: a check that broke silently looks like a pass.
    try { process.stderr.write(`[AEGIS] check-budget could not run its checks — this call was NOT checked (${String((err as Error)?.message ?? err).slice(0, 120)})\n`); } catch {}
    process.exit(0);
  }
}
