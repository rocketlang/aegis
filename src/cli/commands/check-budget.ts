// AEGIS Hook — check-budget
// Called by Claude Code PreToolUse hook before every tool use.
// Default mode (alert): NEVER blocks — only warns to stderr.
// Enforce mode: blocks (exit 2) when budget is exhausted or agent soft-stop threshold hit.
//
// Phase 3: per-agent EWMA projection, 80% alert, 95% soft-stop (V2-064)
// @rule:KAV-009 Projected cost alerts
// @rule:KAV-016 L1 Soft Stop at 95% of agent cap
// @rule:INF-KAV-008 80% alert threshold

import { loadConfig } from "../../core/config";
import { getBudgetState, getAgentCostProjection, requestStop } from "../../core/db";

export default function checkBudget(_args: string[]): void {
  try {
    const config = loadConfig();
    const enforce = config.enforcement?.mode === "enforce";

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
    if (weekly.percent >= 100 && enforce) {
      process.stderr.write(`AEGIS: Weekly budget exhausted — BLOCKED\n`);
      process.exit(2);
    }

    // --- V2-064: Per-agent EWMA projection ---
    // @rule:KAV-009 Projected cost, INF-KAV-008 80% alert, KAV-016 95% soft-stop
    const agentId = process.env.CLAUDE_AGENT_ID || process.env.CLAUDE_SESSION_ID || "unknown";
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
  } catch {
    process.exit(0); // never block on AEGIS internal errors
  }
}
