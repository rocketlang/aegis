// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// session-end — Stop hook
// Fires when Claude Code stops (end_turn, max_turns, error, user interrupt).
// Writes session summary: duration, tool calls, DAN events, stop reason.
//
// @rule:KOS-078 session summary written at stop; duration + DAN count = minimum evidence
//
// Output:
//   ~/.aegis/aegis.db  sessions table  (ended_at, stop_reason, tool_call_count)
//   ~/.aegis/sessions/{session_id}.summary.json  (self-contained)

import { readFileSync, writeFileSync, existsSync, mkdirSync, unlinkSync } from "fs";
import { spawn } from "child_process";
import { join } from "path";
import { getAegisDir, loadConfig } from "../core/config";
import { getDb, getUnacknowledgedBgAgents } from "../core/db";
import { closeTurn, getUnexportedTurns, markExported } from "../telemetry/turn-store";
import { exportSpans } from "../telemetry/otel";
import { assembleSpans } from "../telemetry/assemble-spans";

interface StopPayload {
  session_id?: string;
  stop_reason?: string;
  transcript_path?: string;
  hook_event_name?: string;
}

function sessionsDir(): string {
  const dir = join(getAegisDir(), "sessions");
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  return dir;
}

function summaryPath(sessionId: string): string {
  return join(sessionsDir(), `${sessionId}.summary.json`);
}

// Count lines in JSONL activity log = total tool calls this session
function countActivityLines(sessionId: string): number {
  const logPath = join(sessionsDir(), `${sessionId}.jsonl`);
  if (!existsSync(logPath)) return 0;
  try {
    const content = readFileSync(logPath, "utf-8");
    return content.split("\n").filter((l) => l.trim()).length;
  } catch {
    return 0;
  }
}

// @rule:KOS-078
async function run(): Promise<void> {
  const stdin = (() => {
    try { return readFileSync("/dev/stdin", "utf-8"); } catch { return "{}"; }
  })();

  let payload: StopPayload = {};
  try { payload = JSON.parse(stdin); } catch {}

  // Claude Code v2.1+ does not inject session_id in hook payloads — read from state file
  const currentSessionFile = join(getAegisDir(), "current_session");
  const storedSessionId = existsSync(currentSessionFile)
    ? readFileSync(currentSessionFile, "utf-8").trim()
    : null;
  const sessionId = payload.session_id ?? process.env.CLAUDE_SESSION_ID ?? storedSessionId ?? "unknown";
  const stopReason = payload.stop_reason ?? "unknown";
  const now = new Date().toISOString();

  // @rule:KOS-T095 — background agent guard (smart, layman-friendly)
  // Rules:
  //   • Natural end_turn / max_turns → never block (agents ran to completion)
  //   • user_interrupt (Ctrl+C) → check pending agents with age-based trust:
  //       - spawned < 15 min ago, not yet acknowledged → BLOCK (likely still running)
  //       - spawned 15–45 min ago → soft WARN only (may have finished, user decides)
  //       - spawned > 45 min ago → auto-acknowledge, no block (assume done)
  // Agents auto-clear in PostToolUse when Claude receives their completion notification.
  // User never needs to manually ack in the normal happy path.
  if (stopReason === "user_interrupt" || stopReason === "interrupt") {
    try {
      const pending = getUnacknowledgedBgAgents(sessionId, 90);
      if (pending.length > 0) {
        const now2 = Date.now();
        const fresh = pending.filter(a => (now2 - new Date(a.spawned_at).getTime()) < 15 * 60 * 1000);
        const middle = pending.filter(a => {
          const age = now2 - new Date(a.spawned_at).getTime();
          return age >= 15 * 60 * 1000 && age < 45 * 60 * 1000;
        });

        if (fresh.length > 0) {
          // Hard block — agents spawned <15min ago almost certainly still running
          const list = fresh.map((a, i) => {
            const desc = a.description ?? a.subagent_type ?? `agent-${i + 1}`;
            const age = Math.round((now2 - new Date(a.spawned_at).getTime()) / 60000);
            return `  ${i + 1}. ${desc} — running for ${age}m`;
          }).join("\n");
          process.stdout.write(JSON.stringify({
            decision: "block",
            reason: `AEGIS: ${fresh.length} agent(s) still in progress (spawned <15 min ago). Wait for them to finish, or say "force quit" to exit anyway.\n\nIn progress:\n${list}`,
          }));
          process.exit(0);
        } else if (middle.length > 0) {
          // Soft warn only — agents are 15–45min old, may have finished
          // Don't block, but let Claude tell the user
          const list = middle.map((a, i) => {
            const desc = a.description ?? a.subagent_type ?? `agent-${i + 1}`;
            const age = Math.round((now2 - new Date(a.spawned_at).getTime()) / 60000);
            return `  ${i + 1}. ${desc} (${age}m ago — may have completed)`;
          }).join("\n");
          process.stderr.write(`[KAVACH:bg] NOTE: ${middle.length} background agent(s) from this session:\n${list}\n`);
          // fall through — allow stop
        }
        // >45min agents: auto-acknowledge, say nothing
      }
    } catch {}
  }

  // Load desk context for duration calculation
  const deskPath = join(sessionsDir(), `${sessionId}.desk.json`);
  let registeredAt: string | null = null;
  let deskContext: Record<string, unknown> = {};
  if (existsSync(deskPath)) {
    try {
      deskContext = JSON.parse(readFileSync(deskPath, "utf-8"));
      registeredAt = deskContext.registered_at as string ?? null;
    } catch {}
  }

  const durationMs = registeredAt
    ? new Date(now).getTime() - new Date(registeredAt).getTime()
    : null;

  const toolCallCount = countActivityLines(sessionId);

  // Read DAN event count from DB
  let danEventCount = 0;
  let totalCostUsd = 0;
  try {
    const db = getDb();
    const danRow = db.query(
      "SELECT COUNT(*) as cnt FROM kavach_approvals WHERE session_id=?"
    ).get(sessionId) as { cnt: number } | null;
    danEventCount = danRow?.cnt ?? 0;

    const costRow = db.query(
      "SELECT total_cost_usd FROM sessions WHERE session_id=?"
    ).get(sessionId) as { total_cost_usd: number } | null;
    totalCostUsd = costRow?.total_cost_usd ?? 0;
  } catch {}

  const summary = {
    session_id: sessionId,
    stop_reason: stopReason,
    started_at: registeredAt,
    ended_at: now,
    duration_ms: durationMs,
    duration_human: durationMs != null ? `${Math.round(durationMs / 60000)}m` : null,
    tool_call_count: toolCallCount,
    dan_event_count: danEventCount,
    total_cost_usd: totalCostUsd,
    desk: {
      hostname: deskContext.hostname ?? null,
      cwd: deskContext.cwd ?? null,
      model: deskContext.model ?? null,
      git_remote: deskContext.git_remote ?? null,
      git_branch: deskContext.git_branch ?? null,
    },
    rule_ref: "KOS-078",
  };

  // Write summary file
  writeFileSync(summaryPath(sessionId), JSON.stringify(summary, null, 2));

  // Update sessions table
  try {
    const db = getDb();
    db.run(
      `UPDATE sessions
       SET ended_at=?, stop_reason=?, tool_call_count=?, dan_event_count=?, status='completed'
       WHERE session_id=?`,
      [now, stopReason, toolCallCount, danEventCount, sessionId]
    );
  } catch {}

  // @rule:KOS-091 — export OTLP spans for completed turns, then clean up
  try {
    const cfg = loadConfig();
    if (cfg.otlp?.endpoint) {
      closeTurn(sessionId);
      const turns = getUnexportedTurns(sessionId);
      const spans  = assembleSpans(turns);
      if (spans.length > 0) {
        await exportSpans(
          {
            endpoint:       cfg.otlp.endpoint,
            headers:        cfg.otlp.headers ?? {},
            serviceName:    cfg.otlp.service_name    ?? "kavachos",
            serviceVersion: cfg.otlp.service_version ?? "2.0.0",
            resourceAttrs:  [],
          },
          spans,
        );
        markExported(sessionId);
        process.stderr.write(`[KAVACH:otel] exported ${spans.length} spans → ${cfg.otlp.endpoint}\n`);
      }
    }
  } catch (err) {
    // Non-blocking — OTLP export failure must never prevent session close
    process.stderr.write(`[KAVACH:otel] export failed (non-fatal): ${(err as Error).message}\n`);
  }

  // Clean up state file so the next claude session gets a fresh ID
  try { unlinkSync(currentSessionFile); } catch {}

  // @rule:DRM-003 — spawn dream phase as detached background process (never blocks session close)
  try {
    const child = spawn("bun", ["/root/ankr-dream-phase.ts", sessionId], {
      detached: true,
      stdio: "ignore",
    });
    child.unref();
    process.stderr.write(`[KAVACH:dream] spawned dream-phase for ${sessionId}\n`);
  } catch (err) {
    // Non-blocking — dream phase failure must never prevent session close
    process.stderr.write(`[KAVACH:dream] spawn failed (non-fatal): ${(err as Error).message}\n`);
  }

  process.stderr.write(
    `[KAVACH:session] closed ${sessionId} | reason=${stopReason} | tools=${toolCallCount} | DAN=${danEventCount} | cost=$${totalCostUsd.toFixed(4)} | duration=${summary.duration_human ?? "?"}\n`
  );
}

run().finally(() => process.exit(0));
