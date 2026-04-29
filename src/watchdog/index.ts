// AEGIS Watchdog — Phase 2 daemon for time-based enforcement
// Polls aegis.db every 30 seconds.
// Detects: zombies (idle > timeout), orphans (parent dead), velocity spikes
// Applies: L1 Soft Stop, quarantine, orphan TTL, resume manifests
//
// @rule:KAV-002 Agent lifecycle, KAV-008 quarantine survives restart
// @rule:KAV-012 Orphan detection — parent dead, children still running
// @rule:KAV-013 Zombie detection — idle > max_idle_timeout AND PID absent
// @rule:KAV-019 Always-on watchdog independent of tool call cadence
// @rule:INF-KAV-002 Velocity throttle
// @rule:INF-KAV-007 Orphan state machine transitions

import { getDb, listAgentRows, setAgentState, requestStop, type AgentRow } from "../core/db";
import { loadConfig } from "../core/config";
import { writeManifest } from "./manifest-writer";

// Per-agent cost rate tracking: { agent_id → { cost_snapshot, timestamp }[] }
const _costHistory: Map<string, Array<{ cost: number; ts: number }>> = new Map();

const POLL_INTERVAL_MS = 30_000;

const MAX_IDLE_TIMEOUT_MS = 5 * 60 * 1000;    // 5 min idle → zombie candidate
const MAX_ZOMBIE_TIMEOUT_MS = 2 * 60 * 1000;  // 2 min after zombie → force close
const ORPHAN_TTL_MS = 5 * 60 * 1000;          // 5 min to act before orphan force-close

// In-memory zombie onset tracker (zombie_since per agentId)
const _zombieSince: Map<string, number> = new Map();
// In-memory orphan onset tracker
const _orphanSince: Map<string, number> = new Map();
// Velocity: tool_calls per agent per 60s window
const _velocityWindow: Map<string, Array<number>> = new Map();

function log(msg: string): void {
  process.stdout.write(`[AEGIS:watchdog] ${new Date().toISOString()} ${msg}\n`);
}

// ── Zombie detection (V2-044) ────────────────────────────────────────────────

async function checkZombies(agents: AgentRow[]): Promise<void> {
  const now = Date.now();
  const config = loadConfig();
  const maxIdle = (config.heartbeat?.timeout_seconds ?? 300) * 1000;

  for (const agent of agents) {
    if (agent.state !== "RUNNING") continue;
    const lastSeenMs = new Date(agent.last_seen).getTime();
    const idleMs = now - lastSeenMs;

    if (idleMs < maxIdle) {
      _zombieSince.delete(agent.agent_id);
      continue;
    }

    // Mark as ZOMBIE
    if (agent.state === "RUNNING") {
      log(`ZOMBIE detected: ${agent.agent_id} idle=${Math.round(idleMs / 1000)}s`);
      setAgentState(agent.agent_id, "ZOMBIE", { reason: `idle > ${Math.round(maxIdle / 1000)}s`, rule: "KAV-013" });
      _zombieSince.set(agent.agent_id, now);
    }
  }

  // Check zombies that have been zombie for too long → L3 Hard Stop
  const zombies = agents.filter((a) => a.state === "ZOMBIE");
  for (const z of zombies) {
    const since = _zombieSince.get(z.agent_id) ?? Date.now();
    if (Date.now() - since > MAX_ZOMBIE_TIMEOUT_MS) {
      log(`FORCE_CLOSE zombie: ${z.agent_id}`);
      const manifestPath = await writeManifest(z, "zombie_timeout");
      setAgentState(z.agent_id, "FORCE_CLOSED", { reason: "zombie timeout exceeded", rule: "KAV-013", resume_manifest_path: manifestPath });
      _zombieSince.delete(z.agent_id);
    }
  }
}

// ── Orphan detection (V2-045, V2-046) ───────────────────────────────────────

function checkOrphans(agents: AgentRow[]): void {
  // Build set of terminal agent IDs
  const terminal = new Set(
    agents
      .filter((a) => ["FORCE_CLOSED", "KILLED", "FAILED"].includes(a.state))
      .map((a) => a.agent_id)
  );

  for (const agent of agents) {
    if (!["RUNNING", "QUARANTINED"].includes(agent.state)) continue;
    if (!agent.parent_id) continue;
    if (!terminal.has(agent.parent_id)) continue;

    // Parent is dead — this agent is orphaned
    if (agent.state !== "ORPHAN") {
      log(`ORPHAN detected: ${agent.agent_id} (parent=${agent.parent_id})`);
      setAgentState(agent.agent_id, "ORPHAN", { reason: `parent ${agent.parent_id} is terminal`, rule: "INF-KAV-007" });
      _orphanSince.set(agent.agent_id, Date.now());
    }
  }

  // Orphan TTL enforcement (V2-046) — if no human action within orphan_ttl → L1 Soft Stop
  const orphans = agents.filter((a) => a.state === "ORPHAN");
  for (const orphan of orphans) {
    const since = _orphanSince.get(orphan.agent_id) ?? Date.now();
    if (Date.now() - since > ORPHAN_TTL_MS) {
      log(`ORPHAN TTL: requesting stop for ${orphan.agent_id}`);
      requestStop(orphan.agent_id);
      _orphanSince.delete(orphan.agent_id);
    }
  }
}

// ── Velocity throttle (V2-051) ───────────────────────────────────────────────

function checkVelocity(agents: AgentRow[]): void {
  const now = Date.now();
  const windowMs = 60_000;

  for (const agent of agents) {
    if (agent.state !== "RUNNING") continue;

    // Compute approximate tool_calls per min from DB increments
    // Since we poll every 30s, compare tool_calls snapshots
    const key = agent.agent_id;
    const history = _velocityWindow.get(key) ?? [];
    history.push(agent.tool_calls);
    if (history.length > 3) history.shift(); // keep last 3 snapshots (90s window)
    _velocityWindow.set(key, history);

    if (history.length < 2) continue;
    const rate = ((history[history.length - 1] - history[0]) / ((history.length - 1) * POLL_INTERVAL_MS)) * 60_000;

    if (rate > 120) {
      log(`QUARANTINE velocity: ${agent.agent_id} rate=${Math.round(rate)}/min > 120`);
      setAgentState(agent.agent_id, "QUARANTINED", {
        reason: `tool_call velocity ${Math.round(rate)}/min > 120 limit`,
        rule: "INF-KAV-002",
      });
    } else if (rate > 60) {
      log(`THROTTLE velocity: ${agent.agent_id} rate=${Math.round(rate)}/min > 60`);
      requestStop(agent.agent_id); // L1 Soft Stop via stop_requested flag
    }
  }
}

// ── Cost rate anomaly detection (V2-065) ────────────────────────────────────

// Baseline cost rate per agent type (USD/min). Rough defaults.
const BASELINE_COST_RATE_USD_PER_MIN = 0.01; // ~$0.01/min for Sonnet
const ANOMALY_MULTIPLIER = 2;
const ANOMALY_PERSIST_WINDOWS = 3; // 3 consecutive windows = 90s

const _anomalyCount: Map<string, number> = new Map();

function checkCostAnomalies(agents: AgentRow[]): void {
  for (const agent of agents) {
    if (agent.state !== "RUNNING") continue;

    const history = _costHistory.get(agent.agent_id) ?? [];
    history.push({ cost: agent.budget_used_usd, ts: Date.now() });
    if (history.length > 5) history.shift(); // keep ~2.5 min of data
    _costHistory.set(agent.agent_id, history);

    if (history.length < 2) continue;

    // Compute USD/min rate from last 2 samples
    const oldest = history[0];
    const newest = history[history.length - 1];
    const elapsedMin = (newest.ts - oldest.ts) / 60_000;
    if (elapsedMin < 0.1) continue;
    const rate = (newest.cost - oldest.cost) / elapsedMin;

    if (rate > BASELINE_COST_RATE_USD_PER_MIN * ANOMALY_MULTIPLIER) {
      const count = (_anomalyCount.get(agent.agent_id) ?? 0) + 1;
      _anomalyCount.set(agent.agent_id, count);
      log(`COST ANOMALY: ${agent.agent_id} rate=$${rate.toFixed(5)}/min (${ANOMALY_MULTIPLIER}× baseline) count=${count}`);

      if (count >= ANOMALY_PERSIST_WINDOWS) {
        log(`SOFT_PAUSE: ${agent.agent_id} — cost rate anomaly persisted ${count} windows — INF-KAV-003`);
        requestStop(agent.agent_id);
        _anomalyCount.set(agent.agent_id, 0);
      }
    } else {
      _anomalyCount.set(agent.agent_id, 0); // reset on normal reading
    }
  }
}

// ── Main poll loop ───────────────────────────────────────────────────────────

async function poll(): Promise<void> {
  try {
    const agents = listAgentRows();
    await checkZombies(agents);
    checkOrphans(agents);
    checkVelocity(agents);
    checkCostAnomalies(agents);
  } catch (err) {
    process.stderr.write(`[AEGIS:watchdog] poll error: ${(err as Error).message}\n`);
  }
}

log("AEGIS Watchdog starting — poll interval 30s");
poll(); // immediate first poll
const intervalId = setInterval(poll, POLL_INTERVAL_MS);

// Clean shutdown
process.on("SIGTERM", () => {
  log("SIGTERM received — shutting down");
  clearInterval(intervalId);
  process.exit(0);
});
process.on("SIGINT", () => {
  log("SIGINT received — shutting down");
  clearInterval(intervalId);
  process.exit(0);
});
