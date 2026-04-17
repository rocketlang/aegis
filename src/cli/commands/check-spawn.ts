// AEGIS Hook — check-spawn
// Called by Claude Code PreToolUse hook when the Agent tool is invoked
// Enforces spawn limits per session
// Exit 0 = allow spawn, Exit 2 = block spawn

import { loadConfig } from "../../core/config";
import { getSessionSpawnCount, getBudgetState } from "../../core/db";

export default function checkSpawn(_args: string[]): void {
  const config = loadConfig();

  // Try to identify current session from stdin (Claude Code passes hook context)
  let sessionId = "unknown";
  try {
    // Hook input might come via stdin or env
    sessionId = process.env.CLAUDE_SESSION_ID || "unknown";
  } catch { /* */ }

  // Check spawn count for this session
  const spawns = getSessionSpawnCount(sessionId);
  if (spawns >= config.budget.spawn_limit_per_session) {
    console.error(`AEGIS: Agent spawn limit reached (${spawns}/${config.budget.spawn_limit_per_session}). Blocked. Run 'aegis budget set spawn <N>' to increase.`);
    process.exit(2);
  }

  // Also check daily budget before allowing expensive spawn
  const daily = getBudgetState("daily", config.budget.daily_limit_usd);
  if (daily.remaining_usd < config.budget.cost_estimate_threshold_usd) {
    console.error(`AEGIS: Only $${daily.remaining_usd.toFixed(2)} remaining in daily budget. Agent spawn blocked to prevent overspend.`);
    process.exit(2);
  }

  // Warn if approaching spawn limit
  if (spawns >= config.budget.spawn_limit_per_session * 0.8) {
    console.error(`AEGIS WARNING: ${spawns}/${config.budget.spawn_limit_per_session} agent spawns used this session.`);
  }

  process.exit(0);
}
