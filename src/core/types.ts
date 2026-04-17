// AEGIS — Agentic Execution Governance & Intelligence System
// Core type definitions

export type PlanType = "api" | "max_5x" | "max_20x" | "pro" | "team" | "custom";

export interface AegisConfig {
  plan: PlanType;
  budget: {
    // API mode (dollars)
    daily_limit_usd: number;
    weekly_limit_usd: number;
    monthly_limit_usd: number;
    session_limit_usd: number;
    // Max/Pro mode (tokens and messages per 5-hour window)
    messages_per_5h: number;        // e.g. Max 5x: ~225 Opus msgs per 5h
    tokens_per_5h: number;          // e.g. ~50M tokens per 5h
    weekly_messages: number;        // e.g. weekly cap
    weekly_tokens: number;
    // Common
    spawn_limit_per_session: number;
    spawn_concurrent_max: number;
    cost_estimate_threshold_usd: number;
  };
  heartbeat: {
    timeout_seconds: number;
    action: "pause" | "kill" | "alert";
  };
  pricing_mode: "api" | "max_plan";
  max_plan_discount: number; // multiplier, e.g. 0.2 means 20% of API price
  dashboard: {
    port: number;
    auth: {
      enabled: boolean;
      username: string;
      password: string; // plaintext in local config — hosted only, not committed
    };
  };
  monitor: {
    health_port: number;
    watch_paths: string[];
    poll_interval_ms: number;
  };
  alerts: {
    terminal_bell: boolean;
    webhook_url: string | null;
  };
  enforcement: {
    mode: "alert" | "enforce";     // alert = warn only (SAFE DEFAULT); enforce = auto-kill/pause
    excluded_pids: number[];       // PIDs to never kill (e.g. user's active session)
    excluded_ppids: number[];      // parent PIDs to never kill (protects child claude processes)
    // @rule:NHI-008 — AEGIS wires to registry on budget kill
    registry_url: string | null;
    registry_admin_key: string | null;
    // Services to auto-restart via ankr-ctl after a kill — infrastructure must survive budget kills
    auto_restart_services: string[];
    auto_restart_delay_ms: number;  // grace period before restart (let kill complete)
  };
}

// Window budget — used for Max Plan 5-hour rolling windows
export interface WindowBudget {
  window_type: "5h" | "weekly";
  window_start: string;       // ISO timestamp when window began
  window_end: string;         // when it resets
  messages_used: number;
  messages_limit: number;
  tokens_used: number;
  tokens_limit: number;
  percent: number;            // max(msg%, token%) — whichever is higher
  time_to_reset_s: number;
}

export interface UsageRecord {
  session_id: string;
  timestamp: string;
  model: string;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_creation_tokens: number;
  estimated_cost_usd: number;
  is_agent_spawn: boolean;
  raw_json?: string;
}

export interface SessionInfo {
  session_id: string;
  project_path: string;
  first_seen: string;
  last_activity: string;
  total_cost_usd: number;
  message_count: number;
  agent_spawns: number;
  status: "active" | "paused" | "killed" | "closed";
}

export interface BudgetState {
  period: string; // 'daily:2026-04-17', 'weekly:2026-W16', 'monthly:2026-04'
  spent_usd: number;
  limit_usd: number;
  remaining_usd: number;
  percent: number;
}

export interface AlertEvent {
  id?: number;
  type: "budget_warning" | "budget_breach" | "spawn_limit" | "anomaly" | "heartbeat_timeout" | "kill";
  severity: "info" | "warning" | "critical";
  message: string;
  session_id?: string;
  timestamp: string;
  acknowledged: boolean;
}

export interface AegisStatus {
  daily: BudgetState;
  weekly: BudgetState;
  monthly: BudgetState;
  active_sessions: SessionInfo[];
  recent_alerts: AlertEvent[];
  monitor_uptime_s: number;
}

// Agent Budget Attestation (ABA) — the universal protocol format
export interface AgentBudgetAttestation {
  aba_version: "1.0";
  agent_id: string;
  surface: "cli" | "web" | "api" | "mobile";
  device: string;
  user: string;
  budget: {
    session_limit: number;
    daily_limit: number;
    currency: "USD";
    remaining: number;
  };
  spend: {
    input_tokens: number;
    output_tokens: number;
    cache_read_tokens: number;
    estimated_cost: number;
    model: string;
  };
  agents_spawned: number;
  heartbeat: {
    last_user_input: string;
    mode: "attended" | "unattended" | "abandoned";
    timeout_seconds: number;
  };
  attestation: {
    signed_by: string;
    timestamp: string;
  };
}
