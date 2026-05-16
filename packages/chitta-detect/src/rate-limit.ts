// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// @rule:CG-YK-007 — per-agent scan rate limit prevents scan flooding

const RATE_LIMIT = parseInt(process.env.SCAN_RATE_LIMIT_PER_MIN ?? '200', 10);
const _rateCounts = new Map<string, { count: number; windowStart: number }>();

export function check(agentId: string): boolean {
  if (RATE_LIMIT === 0) return true;
  const now = Date.now();
  const entry = _rateCounts.get(agentId);
  if (!entry || now - entry.windowStart > 60_000) {
    _rateCounts.set(agentId, { count: 1, windowStart: now });
    return true;
  }
  entry.count++;
  return entry.count <= RATE_LIMIT;
}

export interface RateLimitStatus {
  agent_id: string;
  limit: number;
  current_count: number;
  remaining: number;
  window_started_at: string;
  window_resets_at: string;
  throttled: boolean;
}

export function getStatus(agentId: string): RateLimitStatus {
  const now = Date.now();
  const entry = _rateCounts.get(agentId);
  const windowStart = entry && now - entry.windowStart <= 60_000 ? entry.windowStart : now;
  const count = entry && now - entry.windowStart <= 60_000 ? entry.count : 0;
  return {
    agent_id: agentId,
    limit: RATE_LIMIT,
    current_count: count,
    remaining: Math.max(0, RATE_LIMIT - count),
    window_started_at: new Date(windowStart).toISOString(),
    window_resets_at: new Date(windowStart + 60_000).toISOString(),
    throttled: count >= RATE_LIMIT && RATE_LIMIT > 0,
  };
}

export function getAllStatus(): RateLimitStatus[] {
  const now = Date.now();
  const result: RateLimitStatus[] = [];
  for (const [agentId, entry] of _rateCounts.entries()) {
    if (now - entry.windowStart <= 60_000) {
      result.push(getStatus(agentId));
    }
  }
  return result;
}

export function getLimit(): number {
  return RATE_LIMIT;
}
