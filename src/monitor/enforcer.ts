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

    // Anomaly detection — spend rate spike
    if (this.spendRateWindow.length >= 10) {
      const avg = this.spendRateWindow.reduce((a, b) => a + b, 0) / this.spendRateWindow.length;
      if (record.estimated_cost_usd > avg * 5 && record.estimated_cost_usd > 1) {
        this.triggerAlert({
          type: "anomaly",
          severity: "warning",
          message: `Spend spike: $${record.estimated_cost_usd.toFixed(2)} (5x above avg $${avg.toFixed(2)})`,
          session_id: record.session_id,
          timestamp: new Date().toISOString(),
          acknowledged: false,
        });
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
    // Only actually kill if mode is "enforce" — alert mode just logs
    if (this.config.enforcement.mode === "enforce") {
      this.killClaudeProcesses("SIGSTOP");
    }
    this.emit({ type: "pause", data: { session_id, mode: this.config.enforcement.mode } });
  }

  private pauseAll(): void {
    // CRITICAL SAFETY: only auto-kill if user explicitly opted in to enforce mode.
    // Default mode is "alert" — warn loudly but never touch processes.
    if (this.config.enforcement.mode === "enforce") {
      this.killClaudeProcesses("SIGSTOP");
      // @rule:NHI-008 — AEGIS budget kill → registry global pause
      this.notifyRegistry("budget_kill_all", "AEGIS budget exhausted — global kill").catch(() => {});
    } else {
      // In alert mode, just log it very loudly
      console.error(`\n\x1b[31m[AEGIS] BUDGET BREACH — would pause all agents, but enforcement.mode = "alert".\x1b[0m`);
      console.error(`\x1b[31m[AEGIS] To enable auto-enforcement: aegis config enforcement enforce\x1b[0m\n`);
    }
    this.emit({ type: "pause", data: { all: true, mode: this.config.enforcement.mode } });
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

  private killClaudeProcesses(signal: "SIGSTOP" | "SIGKILL" | "SIGCONT"): void {
    try {
      const result = Bun.spawnSync(["pgrep", "-f", "claude"]);
      const pids = result.stdout.toString().trim().split("\n").filter(Boolean);
      const myPid = process.pid;
      const myPpid = process.ppid;
      const excluded = new Set([
        myPid,
        myPpid,
        ...this.config.enforcement.excluded_pids,
        ...this.config.enforcement.excluded_ppids,
      ]);

      for (const pidStr of pids) {
        const pid = parseInt(pidStr);
        if (isNaN(pid)) continue;
        if (excluded.has(pid)) continue;

        // Also exclude processes whose parent is in excluded list
        try {
          const ppidResult = Bun.spawnSync(["ps", "-o", "ppid=", "-p", pidStr]);
          const ppid = parseInt(ppidResult.stdout.toString().trim());
          if (excluded.has(ppid)) continue;
        } catch { /* fall through */ }

        try {
          const sig = signal === "SIGSTOP" ? 19 : signal === "SIGKILL" ? 9 : 18;
          process.kill(pid, sig);
        } catch { /* process already gone */ }
      }
    } catch { /* pgrep not found */ }
  }
}
