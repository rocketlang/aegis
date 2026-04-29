// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// System intelligence endpoint — process count, resource usage, velocity, projections
import type { FastifyInstance } from "fastify";
import { getDb } from "../../core/db";

interface ProcessInfo {
  name: string;
  pid: number;
  ppid: number;
  cpu: number;
  mem_mb: number;
  elapsed: string;
  cmd: string;
}

function getAgentProcesses(): ProcessInfo[] {
  const patterns = ["claude", "codex", "cursor", "copilot", "devin"];
  const procs: ProcessInfo[] = [];
  const myPid = process.pid;

  for (const pattern of patterns) {
    try {
      const result = Bun.spawnSync([
        "ps", "-eo", "pid,ppid,%cpu,rss,etime,comm,args",
        "--no-headers",
      ]);
      const out = result.stdout.toString().split("\n");
      for (const line of out) {
        if (!line.toLowerCase().includes(pattern)) continue;
        if (line.includes("aegis")) continue; // skip aegis itself
        const parts = line.trim().split(/\s+/);
        if (parts.length < 6) continue;
        const pid = parseInt(parts[0]);
        if (pid === myPid) continue;
        const ppid = parseInt(parts[1]);
        const cpu = parseFloat(parts[2]);
        const rss = parseInt(parts[3]);
        const elapsed = parts[4];
        const comm = parts[5];
        const args = parts.slice(6).join(" ").slice(0, 60);
        if (procs.find((p) => p.pid === pid)) continue;
        procs.push({
          name: pattern,
          pid,
          ppid,
          cpu: isNaN(cpu) ? 0 : cpu,
          mem_mb: isNaN(rss) ? 0 : Math.round(rss / 1024),
          elapsed,
          cmd: args || comm,
        });
      }
    } catch { /* */ }
  }

  return procs;
}

export async function registerSystemRoutes(app: FastifyInstance): Promise<void> {
  // Live process list
  app.get("/api/processes", async () => {
    return { processes: getAgentProcesses() };
  });

  // Velocity: token rate, session rate, projected end-of-window spend
  app.get("/api/velocity", async () => {
    const db = getDb();
    const fiveMinAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000).toISOString();

    const rate5m = db.query(`
      SELECT
        COUNT(*) as msgs,
        COALESCE(SUM(input_tokens + output_tokens + cache_read_tokens + cache_creation_tokens), 0) as tokens,
        COALESCE(SUM(estimated_cost_usd), 0) as cost
      FROM usage_log WHERE timestamp >= ?
    `).get(fiveMinAgo) as any;

    const rate1h = db.query(`
      SELECT
        COUNT(*) as msgs,
        COALESCE(SUM(input_tokens + output_tokens + cache_read_tokens + cache_creation_tokens), 0) as tokens,
        COALESCE(SUM(estimated_cost_usd), 0) as cost
      FROM usage_log WHERE timestamp >= ?
    `).get(oneHourAgo) as any;

    return {
      last_5min: {
        messages: rate5m.msgs || 0,
        tokens: rate5m.tokens || 0,
        cost_usd: rate5m.cost || 0,
        tokens_per_min: Math.round((rate5m.tokens || 0) / 5),
        msgs_per_min: ((rate5m.msgs || 0) / 5).toFixed(1),
      },
      last_1h: {
        messages: rate1h.msgs || 0,
        tokens: rate1h.tokens || 0,
        cost_usd: rate1h.cost || 0,
      },
      // Projected spend for next 5h at current 5-min rate
      projected_5h_msgs: Math.round((rate5m.msgs || 0) * 60),
    };
  });

  // Model breakdown — which models are being used
  app.get("/api/models", async () => {
    const db = getDb();
    const today = new Date().toISOString().slice(0, 10);
    const rows = db.query(`
      SELECT
        COALESCE(model, 'unknown') as model,
        COUNT(*) as count,
        SUM(input_tokens + output_tokens + cache_read_tokens + cache_creation_tokens) as tokens,
        SUM(estimated_cost_usd) as cost
      FROM usage_log
      WHERE timestamp >= ?
      GROUP BY model
      ORDER BY count DESC
    `).all(today) as any[];
    return { models: rows };
  });

  // Provider breakdown — Claude vs Codex vs others (by session_id prefix)
  app.get("/api/providers", async () => {
    const db = getDb();
    const today = new Date().toISOString().slice(0, 10);
    const sessions = db.query(`
      SELECT session_id, total_cost_usd, message_count
      FROM sessions
      WHERE last_activity >= ?
    `).all(today) as any[];

    const breakdown: Record<string, { sessions: number; messages: number; cost: number }> = {
      "claude-code": { sessions: 0, messages: 0, cost: 0 },
      "openai-codex": { sessions: 0, messages: 0, cost: 0 },
      "other": { sessions: 0, messages: 0, cost: 0 },
    };

    for (const s of sessions) {
      const key = s.session_id.startsWith("codex-") ? "openai-codex"
        : s.session_id.match(/^[0-9a-f]{8}-/) ? "claude-code"
        : "other";
      breakdown[key].sessions++;
      breakdown[key].messages += s.message_count || 0;
      breakdown[key].cost += s.total_cost_usd || 0;
    }

    return { providers: breakdown };
  });

  // Spend trend — last 7 days
  app.get("/api/trend", async () => {
    const db = getDb();
    const sevenDaysAgo = new Date(Date.now() - 7 * 86400 * 1000).toISOString();
    const rows = db.query(`
      SELECT
        SUBSTR(timestamp, 1, 10) as day,
        COUNT(*) as msgs,
        SUM(input_tokens + output_tokens + cache_read_tokens + cache_creation_tokens) as tokens,
        SUM(estimated_cost_usd) as cost
      FROM usage_log
      WHERE timestamp >= ?
      GROUP BY day
      ORDER BY day
    `).all(sevenDaysAgo) as any[];
    return { days: rows };
  });

  // Composite "system overview" — one call for dashboard efficiency
  app.get("/api/system", async () => {
    const processes = getAgentProcesses();
    const db = getDb();
    const fiveMinAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();
    const velocity = db.query(`
      SELECT
        COUNT(*) as msgs,
        COALESCE(SUM(input_tokens + output_tokens + cache_read_tokens + cache_creation_tokens), 0) as tokens,
        COALESCE(SUM(estimated_cost_usd), 0) as cost
      FROM usage_log WHERE timestamp >= ?
    `).get(fiveMinAgo) as any;

    return {
      process_count: processes.length,
      total_cpu: processes.reduce((a, b) => a + b.cpu, 0).toFixed(1),
      total_mem_mb: processes.reduce((a, b) => a + b.mem_mb, 0),
      processes,
      velocity_5m: {
        messages: velocity.msgs || 0,
        tokens_per_min: Math.round((velocity.tokens || 0) / 5),
        cost_per_hour: ((velocity.cost || 0) * 12).toFixed(2),
      },
    };
  });
}
