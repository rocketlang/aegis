// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// @rule:KAV-085 Full behavioral baseline — tool, bash, path EWMA profiles
// @rule:KAV-YK-026 2σ deviation → soft stop trigger

import { existsSync, readFileSync, writeFileSync, mkdirSync } from "fs";
import { join } from "path";
import { getAegisDir } from "../core/config";

// ── Constants ─────────────────────────────────────────────────────────────────

// Do not flag anomalies until this many observations collected per agent
const BOOTSTRAP_OBSERVATIONS = 50;
// EWMA smoothing — slow to shift; recent data counts less, baseline persists longer
const EWMA_ALPHA = 0.05;
// Sigma threshold for anomaly
const ANOMALY_SIGMA = 2.0;

// ── Types ─────────────────────────────────────────────────────────────────────

export interface BehaviorProfile {
  agent_id: string;
  observation_count: number;
  // EWMA frequency weights per tool name: values sum to ~1 at steady state
  tool_ewma: Record<string, number>;
  // EWMA frequency weights per bash first-token
  bash_token_ewma: Record<string, number>;
  // EWMA frequency weights per normalized path prefix (first 3 components)
  path_prefix_ewma: Record<string, number>;
  last_updated: string;
}

export interface BehaviorObservation {
  tool_name: string;
  bash_first_token?: string;  // first whitespace-delimited token from bash command
  path_prefix?: string;       // file path used (Read/Write/Edit)
}

export interface BehaviorAnomalyResult {
  anomaly: boolean;
  reason?: string;
  sigma?: number;
  observation_count: number;
  bootstrapping: boolean;
  rule_ref: "KAV-085";
}

// ── Persistence ───────────────────────────────────────────────────────────────

function baselinesDir(): string {
  const dir = join(getAegisDir(), "baselines");
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  return dir;
}

function profilePath(agentId: string): string {
  // Sanitize agentId for filesystem — replace path-unsafe chars
  const safe = agentId.replace(/[^a-zA-Z0-9._-]/g, "_");
  return join(baselinesDir(), `${safe}.baseline.json`);
}

function loadProfile(agentId: string): BehaviorProfile {
  const p = profilePath(agentId);
  if (existsSync(p)) {
    try { return JSON.parse(readFileSync(p, "utf-8")) as BehaviorProfile; } catch {}
  }
  return {
    agent_id: agentId,
    observation_count: 0,
    tool_ewma: {},
    bash_token_ewma: {},
    path_prefix_ewma: {},
    last_updated: new Date().toISOString(),
  };
}

function saveProfile(profile: BehaviorProfile): void {
  try {
    writeFileSync(profilePath(profile.agent_id), JSON.stringify(profile, null, 2));
  } catch { /* non-fatal — file state is advisory */ }
}

// ── EWMA helpers ──────────────────────────────────────────────────────────────

// Update EWMA: new observation of `key` → weight 1.0, all others decay
function updateEwmaVocabulary(map: Record<string, number>, key: string): void {
  // Decay all existing keys
  for (const k of Object.keys(map)) {
    map[k] = (1 - EWMA_ALPHA) * map[k];
  }
  // Apply observation
  map[key] = EWMA_ALPHA + (1 - EWMA_ALPHA) * (map[key] ?? 0);
}

// Compute mean and σ over map values; return sigma distance for key
function sigmaDistance(map: Record<string, number>, key: string): number {
  const values = Object.values(map);
  if (values.length < 2) return 0;
  const mean = values.reduce((a, b) => a + b, 0) / values.length;
  const variance = values.reduce((a, b) => a + (b - mean) ** 2, 0) / values.length;
  const sigma = Math.sqrt(variance);
  if (sigma < 1e-6) return 0;
  return Math.abs((map[key] ?? 0) - mean) / sigma;
}

// Extract first whitespace-delimited token from a bash command
export function extractBashFirstToken(command: string): string | undefined {
  const token = command.trim().split(/\s+/)[0];
  // Ignore empty or single-character tokens (likely variables or subshells)
  return token && token.length > 1 ? token : undefined;
}

// Normalize a file path to a 3-component prefix
export function normalizePathPrefix(filePath: string): string {
  const parts = filePath.replace(/\/+/g, "/").split("/").filter(Boolean);
  return "/" + parts.slice(0, 3).join("/");
}

// ── Core observation recorder ─────────────────────────────────────────────────

// @rule:KAV-085 record tool call and check for behavioral deviation
// Returns anomaly result. Call is non-throwing — safe to use in PreToolUse hook.
export function recordObservation(agentId: string, obs: BehaviorObservation): BehaviorAnomalyResult {
  try {
    const profile = loadProfile(agentId);
    const bootstrapping = profile.observation_count < BOOTSTRAP_OBSERVATIONS;

    // Anomaly check BEFORE update — detect deviation from established baseline
    if (!bootstrapping) {
      // New tool never seen before
      if (!(obs.tool_name in profile.tool_ewma)) {
        return {
          anomaly: true,
          reason: `new tool "${obs.tool_name}" not in behavioral baseline (${profile.observation_count} prior observations)`,
          observation_count: profile.observation_count,
          bootstrapping: false,
          rule_ref: "KAV-085",
        };
      }

      // Bash first-token anomaly
      if (obs.bash_first_token && obs.bash_first_token in profile.bash_token_ewma) {
        const s = sigmaDistance(profile.bash_token_ewma, obs.bash_first_token);
        if (s > ANOMALY_SIGMA) {
          return {
            anomaly: true,
            reason: `bash first-token "${obs.bash_first_token}" deviates ${s.toFixed(1)}σ from baseline`,
            sigma: s,
            observation_count: profile.observation_count,
            bootstrapping: false,
            rule_ref: "KAV-085",
          };
        }
      }

      // Path prefix anomaly
      if (obs.path_prefix) {
        const prefix = normalizePathPrefix(obs.path_prefix);
        if (prefix in profile.path_prefix_ewma) {
          const s = sigmaDistance(profile.path_prefix_ewma, prefix);
          if (s > ANOMALY_SIGMA) {
            return {
              anomaly: true,
              reason: `path prefix "${prefix}" deviates ${s.toFixed(1)}σ from baseline`,
              sigma: s,
              observation_count: profile.observation_count,
              bootstrapping: false,
              rule_ref: "KAV-085",
            };
          }
        }
      }
    }

    // Update EWMA profile
    profile.observation_count++;
    updateEwmaVocabulary(profile.tool_ewma, obs.tool_name);
    if (obs.bash_first_token) {
      updateEwmaVocabulary(profile.bash_token_ewma, obs.bash_first_token);
    }
    if (obs.path_prefix) {
      const prefix = normalizePathPrefix(obs.path_prefix);
      updateEwmaVocabulary(profile.path_prefix_ewma, prefix);
    }
    profile.last_updated = new Date().toISOString();
    saveProfile(profile);

    return { anomaly: false, observation_count: profile.observation_count, bootstrapping, rule_ref: "KAV-085" };
  } catch {
    // Never block on baseline errors
    return { anomaly: false, observation_count: 0, bootstrapping: true, rule_ref: "KAV-085" };
  }
}

// ── Watchdog scanner ──────────────────────────────────────────────────────────

export interface BaselineScanResult {
  agent_id: string;
  observation_count: number;
  bootstrapping: boolean;
  anomaly_flag: boolean;      // true if profile has anomalous distribution
  anomaly_detail?: string;
}

// @rule:KAV-085 scan all baseline profiles — called by watchdog each poll
// Returns agents whose tool EWMA distribution is severely skewed (one tool > 95% of calls).
// This catches runaway agents that have locked onto a single tool (e.g. all-Bash loop).
export function scanBehavioralAnomalies(agentIds: string[]): BaselineScanResult[] {
  const results: BaselineScanResult[] = [];
  for (const agentId of agentIds) {
    try {
      const profile = loadProfile(agentId);
      if (profile.observation_count === 0) continue;

      const bootstrapping = profile.observation_count < BOOTSTRAP_OBSERVATIONS;
      let anomaly_flag = false;
      let anomaly_detail: string | undefined;

      if (!bootstrapping) {
        // Detect dominant-tool runaway: one tool has captured > 90% of EWMA weight
        const toolValues = Object.entries(profile.tool_ewma);
        if (toolValues.length > 0) {
          const total = toolValues.reduce((s, [, v]) => s + v, 0);
          for (const [tool, weight] of toolValues) {
            if (total > 0 && weight / total > 0.90) {
              anomaly_flag = true;
              anomaly_detail = `tool "${tool}" dominates at ${Math.round(weight / total * 100)}% of calls`;
              break;
            }
          }
        }
      }

      results.push({ agent_id: agentId, observation_count: profile.observation_count, bootstrapping, anomaly_flag, anomaly_detail });
    } catch { /* skip agent on error */ }
  }
  return results;
}
