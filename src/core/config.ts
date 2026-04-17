import { existsSync, mkdirSync, writeFileSync, readFileSync } from "fs";
import { join } from "path";
import type { AegisConfig } from "./types";

const AEGIS_DIR = join(process.env.HOME || "/root", ".aegis");
const CONFIG_PATH = join(AEGIS_DIR, "config.json");

const DEFAULT_CONFIG: AegisConfig = {
  plan: "max_5x",      // default assumption for ANKR founder
  budget: {
    daily_limit_usd: 100,
    weekly_limit_usd: 400,
    monthly_limit_usd: 1200,
    session_limit_usd: 25,
    // Max 5x defaults (approx — Anthropic doesn't publish exact numbers)
    messages_per_5h: 225,       // ~225 Opus messages per 5h for Max 5x
    tokens_per_5h: 50_000_000,  // ~50M tokens per 5h (conservative)
    weekly_messages: 3150,      // 14 windows/week × 225
    weekly_tokens: 700_000_000, // 14 × 50M
    spawn_limit_per_session: 50,
    spawn_concurrent_max: 20,
    cost_estimate_threshold_usd: 10,
  },
  heartbeat: {
    timeout_seconds: 300,
    action: "alert",
  },
  pricing_mode: "api",
  max_plan_discount: 0.2,
  dashboard: {
    port: 4850,
    auth: {
      enabled: false,
      username: "aegis",
      password: "changeme",
    },
  },
  monitor: {
    health_port: 4851,
    watch_paths: ["~/.claude/projects"],
    poll_interval_ms: 2000,
  },
  alerts: {
    terminal_bell: true,
    webhook_url: null,
  },
  enforcement: {
    mode: "alert",        // SAFE DEFAULT — never auto-kill. User must opt-in via config.
    excluded_pids: [],
    excluded_ppids: [],
    registry_url: "http://localhost:4586",  // @rule:NHI-008 — agent registry endpoint
    registry_admin_key: "ankr-registry-dev-key",
  },
};

export function getAegisDir(): string {
  return AEGIS_DIR;
}

export function getDbPath(): string {
  return join(AEGIS_DIR, "aegis.db");
}

export function ensureAegisDir(): void {
  if (!existsSync(AEGIS_DIR)) {
    mkdirSync(AEGIS_DIR, { recursive: true });
  }
}

export function loadConfig(): AegisConfig {
  ensureAegisDir();
  if (!existsSync(CONFIG_PATH)) {
    writeFileSync(CONFIG_PATH, JSON.stringify(DEFAULT_CONFIG, null, 2));
    return DEFAULT_CONFIG;
  }
  try {
    const raw = readFileSync(CONFIG_PATH, "utf-8");
    const parsed = JSON.parse(raw);
    return { ...DEFAULT_CONFIG, ...parsed, budget: { ...DEFAULT_CONFIG.budget, ...parsed.budget } };
  } catch {
    return DEFAULT_CONFIG;
  }
}

export function saveConfig(config: AegisConfig): void {
  ensureAegisDir();
  writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
}

export function resolveWatchPaths(config: AegisConfig): string[] {
  const home = process.env.HOME || "/root";
  return config.monitor.watch_paths.map((p) => p.replace("~", home));
}
