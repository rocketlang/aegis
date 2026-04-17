// AEGIS Hook — check-budget
// Called by Claude Code PreToolUse hook before every tool use
// Exit 0 = allow, Exit 2 = block (with message to Claude)
// Must be FAST (<50ms) — reads SQLite only

import { loadConfig } from "../../core/config";
import { getBudgetState, getDailySpend } from "../../core/db";

export default function checkBudget(_args: string[]): void {
  const config = loadConfig();

  // Check daily budget
  const daily = getBudgetState("daily", config.budget.daily_limit_usd);
  if (daily.percent >= 100) {
    console.error(`AEGIS: Daily budget exhausted ($${daily.spent_usd.toFixed(2)}/$${daily.limit_usd}). All tool use blocked. Run 'aegis budget set daily <amount>' to increase.`);
    process.exit(2);
  }

  // Check weekly budget
  const weekly = getBudgetState("weekly", config.budget.weekly_limit_usd);
  if (weekly.percent >= 100) {
    console.error(`AEGIS: Weekly budget exhausted ($${weekly.spent_usd.toFixed(2)}/$${weekly.limit_usd}). All tool use blocked.`);
    process.exit(2);
  }

  // Warn at 90% (doesn't block, just prints warning)
  if (daily.percent >= 90) {
    console.error(`AEGIS WARNING: Daily budget at ${daily.percent.toFixed(0)}% ($${daily.spent_usd.toFixed(2)}/$${daily.limit_usd}). Consider wrapping up.`);
  }

  // Allow
  process.exit(0);
}
