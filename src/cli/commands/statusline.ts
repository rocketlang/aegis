// AEGIS — statusline output for Claude Code
// Produces a single-line status string suitable for Claude Code's statusLine hook
// Fast path: reads SQLite only, returns in <50ms

import { loadConfig } from "../../core/config";
import { getBudgetState, getWindowBudget } from "../../core/db";

export default function statusline(_args: string[]): void {
  try {
    const config = loadConfig();
    const isMaxPlan = config.plan && config.plan.startsWith("max");

    let line: string;

    if (isMaxPlan) {
      const w5h = getWindowBudget("5h", config.budget.messages_per_5h, config.budget.tokens_per_5h);
      const resetMin = Math.floor(w5h.time_to_reset_s / 60);
      const resetStr = resetMin >= 60 ? `${Math.floor(resetMin/60)}h${resetMin%60}m` : `${resetMin}m`;

      // Color based on percent — ANSI codes work in most terminals
      const color = w5h.percent >= 90 ? "\x1b[31m" :       // red
                    w5h.percent >= 70 ? "\x1b[33m" :       // yellow
                    "\x1b[32m";                            // green
      const reset = "\x1b[0m";

      line = `${color}◉ AEGIS${reset} ${w5h.messages_used}/${w5h.messages_limit}msg ${color}${w5h.percent.toFixed(0)}%${reset} reset:${resetStr}`;
    } else {
      const daily = getBudgetState("daily", config.budget.daily_limit_usd);
      const color = daily.percent >= 90 ? "\x1b[31m" :
                    daily.percent >= 70 ? "\x1b[33m" :
                    "\x1b[32m";
      const reset = "\x1b[0m";
      line = `${color}◉ AEGIS${reset} $${daily.spent_usd.toFixed(2)}/${daily.limit_usd.toFixed(0)} ${color}${daily.percent.toFixed(0)}%${reset}`;
    }

    // Single line, no newline — Claude Code appends its own formatting
    process.stdout.write(line);
    process.exit(0);
  } catch {
    // Silent fail — don't break status line if AEGIS isn't running
    process.exit(0);
  }
}
