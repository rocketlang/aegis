// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

import { loadConfig } from "../../core/config";
import { getBudgetState, listActiveSessions, getRecentAlerts, getWindowBudget } from "../../core/db";
import { eeStatus } from "../../../ee/license";

function bar(percent: number, width: number = 30): string {
  const filled = Math.round((percent / 100) * width);
  const empty = width - filled;
  const color = percent >= 90 ? "\x1b[31m" : percent >= 70 ? "\x1b[33m" : "\x1b[32m";
  return `${color}[${"=".repeat(filled)}${".".repeat(empty)}]\x1b[0m`;
}

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return `${h}h ${m}m`;
}

function formatTokens(tokens: number): string {
  if (tokens >= 1_000_000_000) return `${(tokens / 1_000_000_000).toFixed(2)}B`;
  if (tokens >= 1_000_000) return `${(tokens / 1_000_000).toFixed(1)}M`;
  if (tokens >= 1_000) return `${(tokens / 1_000).toFixed(0)}K`;
  return tokens.toString();
}

function renderMaxPlan(config: any): void {
  const window5h = getWindowBudget("5h", config.budget.messages_per_5h, config.budget.tokens_per_5h);
  const weekly = getWindowBudget("weekly", config.budget.weekly_messages, config.budget.weekly_tokens);

  console.log(`
\x1b[1m\x1b[36m  AEGIS\x1b[0m — Max Plan (${config.plan})
${"─".repeat(60)}

  \x1b[1m5h window:\x1b[0m   ${bar(window5h.percent)} ${window5h.percent.toFixed(0)}%
    Messages:  ${window5h.messages_used} / ${window5h.messages_limit}
    Tokens:    ${formatTokens(window5h.tokens_used)} / ${formatTokens(window5h.tokens_limit)}
    Resets in: ${formatDuration(window5h.time_to_reset_s)}

  \x1b[1mWeekly:\x1b[0m      ${bar(weekly.percent)} ${weekly.percent.toFixed(0)}%
    Messages:  ${weekly.messages_used} / ${weekly.messages_limit}
    Tokens:    ${formatTokens(weekly.tokens_used)} / ${formatTokens(weekly.tokens_limit)}
`);
}

function renderApiPlan(config: any): void {
  const daily = getBudgetState("daily", config.budget.daily_limit_usd);
  const weekly = getBudgetState("weekly", config.budget.weekly_limit_usd);
  const monthly = getBudgetState("monthly", config.budget.monthly_limit_usd);

  console.log(`
\x1b[1m\x1b[36m  AEGIS\x1b[0m — API Plan
${"─".repeat(60)}

  \x1b[1mToday:\x1b[0m   $${daily.spent_usd.toFixed(2)} / $${daily.limit_usd}  ${bar(daily.percent)} ${daily.percent.toFixed(0)}%
  \x1b[1mWeek:\x1b[0m    $${weekly.spent_usd.toFixed(2)} / $${weekly.limit_usd}  ${bar(weekly.percent)} ${weekly.percent.toFixed(0)}%
  \x1b[1mMonth:\x1b[0m   $${monthly.spent_usd.toFixed(2)} / $${monthly.limit_usd}  ${bar(monthly.percent)} ${monthly.percent.toFixed(0)}%
`);
}

export default function status(_args: string[]): void {
  const config = loadConfig();
  const isMaxPlan = config.plan && config.plan.startsWith("max");

  if (isMaxPlan) {
    renderMaxPlan(config);
  } else {
    renderApiPlan(config);
  }

  const sessions = listActiveSessions();
  const alerts = getRecentAlerts(5);

  console.log(`${"─".repeat(60)}`);
  console.log(`  \x1b[1mActive Sessions:\x1b[0m ${sessions.length}`);

  for (const s of sessions.slice(0, 10)) {
    const statusIcon = s.status === "paused" ? "\x1b[33mPAUSED\x1b[0m" :
                       s.status === "killed" ? "\x1b[31mKILLED\x1b[0m" :
                       "\x1b[32mACTIVE\x1b[0m";
    const costDisplay = isMaxPlan ? `${s.message_count} msgs` : `$${s.total_cost_usd.toFixed(2)}`;
    console.log(`    [${s.session_id.slice(0, 8)}] ${costDisplay}  ${s.agent_spawns} spawns  [${statusIcon}]`);
  }
  if (sessions.length > 10) {
    console.log(`    ... and ${sessions.length - 10} more`);
  }

  if (alerts.length > 0) {
    console.log(`\n${"─".repeat(60)}`);
    console.log(`  \x1b[1mRecent Alerts:\x1b[0m`);
    for (const a of alerts) {
      const icon = a.severity === "critical" ? "\x1b[31mCRIT\x1b[0m" :
                   a.severity === "warning" ? "\x1b[33mWARN\x1b[0m" :
                   "\x1b[36mINFO\x1b[0m";
      const time = a.timestamp.slice(11, 19);
      console.log(`    [${icon}] ${time} ${a.message}`);
    }
  }

  console.log(`  \x1b[1mEE:\x1b[0m ${eeStatus()}`);
  console.log();
}
