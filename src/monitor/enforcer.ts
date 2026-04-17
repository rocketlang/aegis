// AEGIS Monitor — Budget Enforcer
// Checks budget rules after each usage event, triggers actions

import { loadConfig } from "../core/config";
import { getBudgetState, addAlert, getDailySpend, getSession, setSessionStatus } from "../core/db";
import type { UsageRecord, AlertEvent, AegisConfig } from "../core/types";

export type EnforcerEvent = {
  type: "usage" | "alert" | "kill" | "pause";
  data: any;
};

export type EnforcerCallback = (event: EnforcerEvent) => void;

export class BudgetEnforcer {
  private config: AegisConfig;
  private listeners: EnforcerCallback[] = [];
  private lastAlertTime = new Map<string, number>(); // debounce alerts
  private spendRateWindow: number[] = []; // last N spend amounts for anomaly detection

  constructor() {
    this.config = loadConfig();
  }

  on(callback: EnforcerCallback): void {
    this.listeners.push(callback);
  }

  private emit(event: EnforcerEvent): void {
    for (const cb of this.listeners) {
      try { cb(event); } catch { /* listener error */ }
    }
  }

  check(record: UsageRecord): void {
    this.config = loadConfig(); // reload on each check (hot config)
    this.spendRateWindow.push(record.estimated_cost_usd);
    if (this.spendRateWindow.length > 100) this.spendRateWindow.shift();

    this.emit({ type: "usage", data: record });

    // Check session budget
    const session = getSession(record.session_id);
    if (session && session.total_cost_usd > this.config.budget.session_limit_usd) {
      this.triggerAlert({
        type: "budget_breach",
        severity: "critical",
        message: `Session ${record.session_id.slice(0, 8)} exceeded $${this.config.budget.session_limit_usd} limit (spent: $${session.total_cost_usd.toFixed(2)})`,
        session_id: record.session_id,
        timestamp: new Date().toISOString(),
        acknowledged: false,
      });
      this.pauseSession(record.session_id);
    }

    // Check daily budget
    const daily = getBudgetState("daily", this.config.budget.daily_limit_usd);
    if (daily.percent >= 100) {
      this.triggerAlert({
        type: "budget_breach",
        severity: "critical",
        message: `Daily budget exhausted: $${daily.spent_usd.toFixed(2)} / $${daily.limit_usd}`,
        timestamp: new Date().toISOString(),
        acknowledged: false,
      });
      this.pauseAll();
    } else if (daily.percent >= 80) {
      this.triggerAlert({
        type: "budget_warning",
        severity: "warning",
        message: `Daily budget at ${daily.percent.toFixed(0)}%: $${daily.spent_usd.toFixed(2)} / $${daily.limit_usd}`,
        timestamp: new Date().toISOString(),
        acknowledged: false,
      });
    }

    // Check weekly budget
    const weekly = getBudgetState("weekly", this.config.budget.weekly_limit_usd);
    if (weekly.percent >= 100) {
      this.triggerAlert({
        type: "budget_breach",
        severity: "critical",
        message: `Weekly budget exhausted: $${weekly.spent_usd.toFixed(2)} / $${weekly.limit_usd}`,
        timestamp: new Date().toISOString(),
        acknowledged: false,
      });
      this.pauseAll();
    }

    // Anomaly detection — spend burst (3x average, $0.10 minimum to avoid noise)
    if (this.spendRateWindow.length >= 10) {
      const avg = this.spendRateWindow.reduce((a, b) => a + b, 0) / this.spendRateWindow.length;
      if (record.estimated_cost_usd > avg * 3 && record.estimated_cost_usd > 0.10) {
        this.triggerAlert({
          type: "anomaly",
          severity: "critical",   // burst = critical, not just warning — triggers kill in enforce mode
          message: `Spend burst: $${record.estimated_cost_usd.toFixed(4)} (${(record.estimated_cost_usd/avg).toFixed(1)}x above avg $${avg.toFixed(4)})`,
          session_id: record.session_id,
          timestamp: new Date().toISOString(),
          acknowledged: false,
        });
        // Burst is a kill trigger in enforce mode, same as budget breach
        this.pauseAll();
      }
    }

    // Spawn limit check
    if (record.is_agent_spawn && session) {
      if (session.agent_spawns >= this.config.budget.spawn_limit_per_session) {
        this.triggerAlert({
          type: "spawn_limit",
          severity: "warning",
          message: `Session ${record.session_id.slice(0, 8)} hit spawn limit: ${session.agent_spawns}/${this.config.budget.spawn_limit_per_session}`,
          session_id: record.session_id,
          timestamp: new Date().toISOString(),
          acknowledged: false,
        });
      }
    }
  }

  private triggerAlert(alert: AlertEvent): void {
    // Debounce — don't fire same alert type more than once per 60s
    const key = `${alert.type}:${alert.session_id || "global"}`;
    const now = Date.now();
    const last = this.lastAlertTime.get(key) || 0;
    if (now - last < 60_000) return;
    this.lastAlertTime.set(key, now);

    addAlert(alert);
    this.emit({ type: "alert", data: alert });

    if (this.config.alerts.terminal_bell) {
      process.stdout.write("\x07"); // bell
    }

    if (this.config.alerts.webhook_url) {
      fetch(this.config.alerts.webhook_url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(alert),
      }).catch(() => { /* webhook failed silently */ });
    }
  }

  private pauseSession(session_id: string): void {
    setSessionStatus(session_id, "paused");
    if (this.config.enforcement.mode === "enforce") {
      // Session budget breach → kill the specific session's processes
      this.killAllAgentProcesses("budget_session", `session ${session_id} exceeded limit`);
    }
    this.emit({ type: "kill", data: { session_id, mode: this.config.enforcement.mode, reason: "session_budget_exceeded" } });
  }

  private pauseAll(): void {
    if (this.config.enforcement.mode === "enforce") {
      // Budget exhausted or burst → hard kill everything
      this.killAllAgentProcesses("budget_global", "daily/weekly budget exhausted or spend burst detected");
      this.notifyRegistry("budget_kill_all", "AEGIS budget exhausted — global kill").catch(() => {});
    } else {
      console.error(`\n\x1b[31m[AEGIS] BUDGET BREACH — enforcement.mode = "alert", no kill.\x1b[0m`);
      console.error(`\x1b[31m[AEGIS] To enable auto-kill: set enforcement.mode = "enforce" in ~/.aegis/config.json\x1b[0m\n`);
    }
    this.emit({ type: "kill", data: { all: true, mode: this.config.enforcement.mode } });
  }

  // Hard kill all Claude Code agents + subagents (budget breach or burst)
  // Kills: claude process tree + bun subagents spawned by Agent tool
  private killAllAgentProcesses(trigger: string, reason: string): void {
    console.error(`\n\x1b[31m[AEGIS] KILL — trigger: ${trigger} — ${reason}\x1b[0m`);

    // Pattern 1: claude CLI process and all children
    this.killByPattern("claude", "SIGKILL");

    // Pattern 2: bun processes running ankr subagents (spawned by Agent tool)
    this.killByPattern("ankr-agent-registry", "SIGKILL");

    // Pattern 3: any bun/node process running as a claude subagent
    // These are identified by being children of the claude process group
    this.killOrphanedSubagents();

    console.error(`\x1b[31m[AEGIS] All agent processes killed. Session terminated.\x1b[0m\n`);
  }

  // @rule:NHI-008 — notify agent registry on budget kill so it can sleep/revoke agents
  private async notifyRegistry(event: string, reason: string): Promise<void> {
    const { registry_url, registry_admin_key } = this.config.enforcement;
    if (!registry_url) return;
    try {
      // Fire a SENSE event to the registry — it will act on it based on its own rules
      await fetch(`${registry_url}/api/v2/forja/sense/emit`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Admin-Key": registry_admin_key ?? "",
        },
        body: JSON.stringify({
          event_type: "agent.slept",
          before_state: "active",
          after_state: "sleeping",
          payload: { source: "aegis", event, reason },
          source: "aegis-enforcer",
        }),
      });
    } catch { /* registry may not be running — non-fatal */ }
  }

  private killByPattern(pattern: string, signal: "SIGKILL" | "SIGTERM"): void {
    try {
      const result = Bun.spawnSync(["pgrep", "-f", pattern]);
      const pids = result.stdout.toString().trim().split("\n").filter(Boolean);
      const excluded = this.buildExcludedSet();
      const sig = signal === "SIGKILL" ? 9 : 15;

      for (const pidStr of pids) {
        const pid = parseInt(pidStr);
        if (isNaN(pid) || excluded.has(pid)) continue;
        try {
          // Kill entire process group — catches all children/subagents
          process.kill(-pid, sig);
        } catch {
          // Fallback: kill just the process if group kill fails
          try { process.kill(pid, sig); } catch { /* already gone */ }
        }
      }
    } catch { /* pgrep not available */ }
  }

  // Kill bun/node processes that are children of claude but not in registry
  // These are subagents spawned by the Agent tool mid-session
  private killOrphanedSubagents(): void {
    try {
      // Find all bun/node processes whose parent is a claude process
      const claudePids = Bun.spawnSync(["pgrep", "-f", "claude"])
        .stdout.toString().trim().split("\n").filter(Boolean);

      for (const cpid of claudePids) {
        // Get all children of this claude process
        const children = Bun.spawnSync(["pgrep", "-P", cpid])
          .stdout.toString().trim().split("\n").filter(Boolean);
        const excluded = this.buildExcludedSet();
        for (const child of children) {
          const pid = parseInt(child);
          if (isNaN(pid) || excluded.has(pid)) continue;
          try { process.kill(pid, 9); } catch { /* already gone */ }
        }
      }
    } catch { /* non-fatal */ }
  }

  private buildExcludedSet(): Set<number> {
    return new Set([
      process.pid,
      process.ppid,
      ...this.config.enforcement.excluded_pids,
      ...this.config.enforcement.excluded_ppids,
    ]);
  }
}
