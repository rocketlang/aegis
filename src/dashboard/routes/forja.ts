// Forja Protocol v2.0 — KAVACH four-endpoint implementation
// @rule:KAV-002 Agent lifecycle registry — STATE reflects live registry state
// @rule:KAV-001 Pre-execution intercept — PROOF verifies @rule annotation coverage
// @rule:KAV-019 Always-on watchdog — STATE exposes watchdog health
// @rule:KAV-YK-009 Agent transaction model — SENSE fires lifecycle events

import type { FastifyInstance } from "fastify";
import { readFileSync, readdirSync, existsSync } from "fs";
import { join } from "path";
import { loadConfig } from "../../core/config";
import {
  listAgentRows,
  getRecentAlerts,
  getBudgetState,
  listActiveSessions,
} from "../../core/db";
import { broadcast } from "../../core/events";

// ── SENSE event ring buffer (last 200 events) ────────────────────────────────
const SENSE_RING: Array<{ event: string; payload: unknown; ts: string }> = [];
const SENSE_RING_MAX = 200;

// CA-003: SENSE events carry before_snapshot / after_snapshot when provided
export interface SensePayload {
  before_snapshot?: unknown;
  after_snapshot?: unknown;
  delta?: unknown;
  [key: string]: unknown;
}

export function emitSense(event: string, payload: SensePayload): void {
  const entry = { event, payload, ts: new Date().toISOString() };
  SENSE_RING.push(entry);
  if (SENSE_RING.length > SENSE_RING_MAX) SENSE_RING.shift();
  broadcast("sense", entry);
}

// ── PROOF: collect @rule annotations from source tree ────────────────────────
const EXPECTED_RULES = new Set([
  // SHASTRA
  "KAV-001", "KAV-002", "KAV-003", "KAV-004", "KAV-005",
  "KAV-006", "KAV-007", "KAV-008", "KAV-009", "KAV-010",
  "KAV-011", "KAV-012", "KAV-013", "KAV-014", "KAV-015",
  "KAV-016", "KAV-017", "KAV-018", "KAV-019", "KAV-020",
  "KAV-061", "KAV-063", "KAV-064", "KAV-066",
  "KAV-067", "KAV-068", "KAV-069", "KAV-070",
  // YUKTI
  "KAV-YK-001", "KAV-YK-002", "KAV-YK-003", "KAV-YK-004", "KAV-YK-005",
  "KAV-YK-006", "KAV-YK-007", "KAV-YK-008", "KAV-YK-009", "KAV-YK-010",
  "KAV-YK-012", "KAV-YK-013", "KAV-YK-014",
  // VIVEKA (inference)
  "INF-KAV-001", "INF-KAV-002", "INF-KAV-003", "INF-KAV-004",
  "INF-KAV-005", "INF-KAV-006", "INF-KAV-007", "INF-KAV-008",
]);

function collectAnnotations(dir: string): Map<string, string[]> {
  const found = new Map<string, string[]>();
  if (!existsSync(dir)) return found;
  const entries = readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      for (const [k, v] of collectAnnotations(full)) {
        const existing = found.get(k) ?? [];
        found.set(k, [...existing, ...v]);
      }
    } else if (entry.name.endsWith(".ts") && !entry.name.endsWith(".test.ts")) {
      try {
        const src = readFileSync(full, "utf-8");
        // match @rule:KAV-NNN, @rule:KAV-YK-NNN, @rule:INF-KAV-NNN
        const matches = src.matchAll(/@rule:((?:INF-)?KAV-(?:YK-)?\d+)/g);
        for (const m of matches) {
          const ruleId = m[1];
          const existing = found.get(ruleId) ?? [];
          found.set(ruleId, [...existing, full.replace(dir, "src")]);
        }
      } catch { /* skip unreadable */ }
    }
  }
  return found;
}

// ── Operator capability matrix ────────────────────────────────────────────────
// @rule:KAV-004 Quarantine human release gate
const OPERATOR_CAPABILITIES = {
  admin: {
    can_release_quarantine: true,
    can_raise_budget: true,
    can_kill_agent: true,
    can_override_depth_limit: true,
    can_unlock_valve: true,
    can_approve_dan4: true,
  },
  operator: {
    can_release_quarantine: true,
    can_raise_budget: false,
    can_kill_agent: true,
    can_override_depth_limit: false,
    can_unlock_valve: false,
    can_approve_dan4: false,
  },
  viewer: {
    can_release_quarantine: false,
    can_raise_budget: false,
    can_kill_agent: false,
    can_override_depth_limit: false,
    can_unlock_valve: false,
    can_approve_dan4: false,
  },
} as const;

type OperatorRole = keyof typeof OPERATOR_CAPABILITIES;

function resolveRole(userId: string, config: ReturnType<typeof loadConfig>): OperatorRole {
  const admins = (config as any).operators?.admins ?? [];
  const operators = (config as any).operators?.operators ?? [];
  if (admins.includes(userId)) return "admin";
  if (operators.includes(userId)) return "operator";
  return "viewer";
}

// ── Route registration ────────────────────────────────────────────────────────
export function registerForjaRoutes(app: FastifyInstance): void {
  const config = loadConfig();
  const srcDir = join(import.meta.dir, "../../");

  // ── GET /api/v2/forja/state ───────────────────────────────────────────────
  // @rule:KAV-002 All agents must register before first tool call
  // @rule:KAV-YK-009 Agent transaction model observability
  app.get("/api/v2/forja/state", async () => {
    const t0 = Date.now();
    const agents = listAgentRows();
    const running = agents.filter((a) => a.state === "RUNNING");
    const quarantined = agents.filter((a) => a.state === "QUARANTINED");
    const zombies = agents.filter((a) => a.state === "ZOMBIE");
    const orphans = agents.filter((a) => a.state === "ORPHAN");
    const forceClosed = agents.filter((a) => a.state === "FORCE_CLOSED");
    const totalViolations = agents.reduce((s, a) => s + a.violation_count, 0);
    const totalCost = agents.reduce((s, a) => s + a.budget_used, 0);
    const sessions = listActiveSessions();
    const alerts = getRecentAlerts(5);
    const budget = getBudgetState("daily", config.budget.daily_limit_usd);

    const watchdogRunning = agents.some(
      (a) => Date.now() - new Date(a.last_seen).getTime() < 90_000
    ) || sessions.length > 0;

    return {
      service: "xshieldai-kavach",
      version: "2.0.0",
      forja_version: "2.0",
      trust_mask: 255,
      trust_mask_schema: "ankr-trust-32bit-v1",
      status: "running",
      timestamp: new Date().toISOString(),
      can_answer: [
        "Is this agent authorised to execute this tool call?",
        "What is the current cost and token usage for this agent?",
        "Which agents are currently ZOMBIE or ORPHAN?",
        "Is a dangerous action pending human approval right now?",
        "What is the projected session cost at current burn rate?",
      ],
      capability_manifest: {
        enforcement_mode: config.enforcement?.mode ?? "alert",
        hooks_active: ["PreToolUse"],
        modules: ["GOVERNOR", "SHIELD", "SANDBOX", "WATCHDOG"],
        gates: ["check-budget", "check-spawn", "check-shield"],
      },
      live_state: {
        agents_running: running.length,
        agents_quarantined: quarantined.length,
        agents_zombie: zombies.length,
        agents_orphan: orphans.length,
        agents_force_closed: forceClosed.length,
        active_sessions: sessions.length,
        total_violations_today: totalViolations,
        total_cost_usd_today: parseFloat(totalCost.toFixed(6)),
        budget_remaining_usd: Math.max(0, (config.budget.daily_limit_usd ?? 100) - (budget?.used ?? 0)),
        violation_rate_per_hour: agents.length > 0
          ? parseFloat((totalViolations / Math.max(1, agents.length) * 60).toFixed(2))
          : 0,
        watchdog_healthy: watchdogRunning,
        recent_alerts: alerts.length,
      },
      sense_ring_depth: SENSE_RING.length,
      _meta: { computed_at: new Date().toISOString(), duration_ms: Date.now() - t0, trust_mask_applied: 255 },
    };
  });

  // ── GET /api/v2/forja/trust/:userId ──────────────────────────────────────
  // @rule:KAV-004 Quarantine human release requires explicit operator role
  app.get<{ Params: { userId: string } }>("/api/v2/forja/trust/:userId", async (req) => {
    const { userId } = req.params;
    const role = resolveRole(userId, config);
    const perms = OPERATOR_CAPABILITIES[role];
    const agents = listAgentRows();
    const quarantinedAgents = agents.filter((a) => a.state === "QUARANTINED");

    const t0 = Date.now();
    return {
      user_id: userId,
      role,
      trust_mask: role === "admin" ? 63 : role === "operator" ? 7 : 1,
      permissions: perms,
      context: {
        quarantine_queue_depth: quarantinedAgents.length,
        quarantined_agent_ids: quarantinedAgents.map((a) => a.agent_id),
        enforcement_mode: config.enforcement?.mode ?? "alert",
      },
      token_valid_until: new Date(Date.now() + 15 * 60 * 1000).toISOString(),
      _meta: { computed_at: new Date().toISOString(), duration_ms: Date.now() - t0, trust_mask_applied: role === "admin" ? 63 : role === "operator" ? 7 : 1 },
    };
  });

  // ── POST /api/v2/forja/sense/emit ─────────────────────────────────────────
  // @rule:KAV-019 Always-on daemon fires SENSE events on lifecycle transitions
  // @rule:KAV-YK-001 Event-driven posture propagation
  app.post("/api/v2/forja/sense/emit", async (req, reply) => {
    const body = req.body as {
      event?: string;
      payload?: unknown;
      source?: string;
    };
    if (!body?.event) {
      return reply.code(400).send({ error: "event field required" });
    }

    const ALLOWED_EVENTS = new Set([
      "AGENT_REGISTERED",
      "AGENT_QUARANTINED",
      "AGENT_COMPLETED",
      "AGENT_FORCE_CLOSED",
      "BUDGET_WARNING",
      "BUDGET_SOFT_STOP",
      "ORPHAN_DETECTED",
      "ZOMBIE_CLOSED",
      "INJECTION_DETECTED",
      "DAN_GATE_TRIGGERED",
      "DAN_ALLOWED",
      "DAN_BLOCKED",
      "VALVE_THROTTLED",
      "VALVE_LOCKED",
      "VELOCITY_SPIKE",
    ]);

    if (!ALLOWED_EVENTS.has(body.event)) {
      return reply.code(422).send({
        error: `Unknown SENSE event: ${body.event}`,
        allowed: [...ALLOWED_EVENTS],
      });
    }

    emitSense(body.event, {
      ...(body.payload as object ?? {}),
      source: body.source ?? "external",
    });

    return { ok: true, event: body.event, ts: new Date().toISOString() };
  });

  // GET /api/v2/forja/sense/recent — ring buffer read
  app.get("/api/v2/forja/sense/recent", async (req) => {
    const limit = Math.min(parseInt((req.query as any).limit ?? "50"), 200);
    return { events: SENSE_RING.slice(-limit), total: SENSE_RING.length };
  });

  // ── GET /api/v2/forja/proof ───────────────────────────────────────────────
  // @rule:KAV-001 Pre-execution supremacy — verify every rule has a code annotation
  // @rule:KAV-020 Audit trail for rule coverage
  app.get("/api/v2/forja/proof", async () => {
    const annotations = collectAnnotations(srcDir);
    const covered = new Set<string>();
    const uncovered = new Set<string>();
    const ruleLocations: Record<string, string[]> = {};

    for (const ruleId of EXPECTED_RULES) {
      const locs = annotations.get(ruleId);
      if (locs && locs.length > 0) {
        covered.add(ruleId);
        ruleLocations[ruleId] = locs;
      } else {
        uncovered.add(ruleId);
      }
    }

    const coverage = EXPECTED_RULES.size > 0
      ? Math.round((covered.size / EXPECTED_RULES.size) * 100)
      : 0;

    // Also report any @rule annotations that reference IDs not in EXPECTED_RULES
    const extraAnnotations: string[] = [];
    for (const [id] of annotations) {
      if (!EXPECTED_RULES.has(id)) extraAnnotations.push(id);
    }

    // CA-001: overflow_granthx_ref when rule_locations would be large (> 50 entries)
    const locationCount = Object.keys(ruleLocations).length;
    const locationsPayload = locationCount > 50
      ? { overflow_granthx_ref: `granthx://kavach/proof/rule_locations?count=${locationCount}` }
      : { rule_locations: ruleLocations };

    return {
      proof_schema: "kavach-proof-v1",
      timestamp: new Date().toISOString(),
      logics_doc: "proposals/xshieldai-kavach--logics--formal--2026-04-29.md",
      total_rules_expected: EXPECTED_RULES.size,
      rules_covered: covered.size,
      rules_missing: uncovered.size,
      coverage_pct: coverage,
      proof_status: coverage >= 90 ? "PASS" : coverage >= 70 ? "PARTIAL" : "FAIL",
      covered: [...covered].sort(),
      missing: [...uncovered].sort(),
      extra_annotations: extraAnnotations.sort(),
      ...locationsPayload,
      _meta: { computed_at: new Date().toISOString(), trust_mask_applied: 255 },
    };
  });
}
