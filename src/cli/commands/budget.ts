// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

import { loadConfig, saveConfig } from "../../core/config";
import { getBudgetState } from "../../core/db";

export default function budget(args: string[]): void {
  const subcommand = args[0] || "show";

  if (subcommand === "show") {
    const config = loadConfig();
    const daily = getBudgetState("daily", config.budget.daily_limit_usd);
    const weekly = getBudgetState("weekly", config.budget.weekly_limit_usd);
    const monthly = getBudgetState("monthly", config.budget.monthly_limit_usd);

    console.log(`
\x1b[1mAEGIS Budget Configuration\x1b[0m
${"─".repeat(40)}
  Daily limit:    $${config.budget.daily_limit_usd}    (spent: $${daily.spent_usd.toFixed(2)})
  Weekly limit:   $${config.budget.weekly_limit_usd}   (spent: $${weekly.spent_usd.toFixed(2)})
  Monthly limit:  $${config.budget.monthly_limit_usd}  (spent: $${monthly.spent_usd.toFixed(2)})
  Session limit:  $${config.budget.session_limit_usd}
  Spawn limit:    ${config.budget.spawn_limit_per_session} per session
  Concurrent max: ${config.budget.spawn_concurrent_max} agents
  Pricing mode:   ${config.pricing_mode}${config.pricing_mode === "max_plan" ? ` (${config.max_plan_discount * 100}% of API price)` : ""}

\x1b[1mWarning Thresholds\x1b[0m
  80% → Warning alert
  100% → Hard stop (SIGSTOP all agents)

\x1b[1mTo change:\x1b[0m
  aegis budget set daily 50
  aegis budget set weekly 200
  aegis budget set session 10
  aegis budget set spawn 20
`);
    return;
  }

  if (subcommand === "set") {
    const field = args[1];
    const value = parseFloat(args[2]);

    if (!field || isNaN(value)) {
      console.error("Usage: aegis budget set <daily|weekly|monthly|session|spawn> <amount>");
      process.exit(1);
    }

    const config = loadConfig();
    switch (field) {
      case "daily":   config.budget.daily_limit_usd = value; break;
      case "weekly":  config.budget.weekly_limit_usd = value; break;
      case "monthly": config.budget.monthly_limit_usd = value; break;
      case "session": config.budget.session_limit_usd = value; break;
      case "spawn":   config.budget.spawn_limit_per_session = value; break;
      default:
        console.error(`Unknown field: ${field}. Use: daily, weekly, monthly, session, spawn`);
        process.exit(1);
    }

    saveConfig(config);
    console.log(`[AEGIS] Budget ${field} set to ${value}`);
    return;
  }

  console.error(`Unknown subcommand: ${subcommand}. Use: show, set`);
}
