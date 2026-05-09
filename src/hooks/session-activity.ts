// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// session-activity — PostToolUse hook (all tools)
// Every tool call result is appended to a per-session JSONL file.
// This is the continuous audit trail for 1000 concurrent sessions.
//
// @rule:KOS-077 every tool call appended to ~/.aegis/sessions/{session_id}.jsonl
//               per-session JSONL = offline-verifiable, no DB contention across sessions
//
// Output: ~/.aegis/sessions/{session_id}.jsonl (one JSON object per line)

import { readFileSync, writeFileSync, appendFileSync, existsSync, mkdirSync, renameSync } from "fs";
import { join } from "path";
import { getAegisDir } from "../core/config";
import { getDb } from "../core/db";
import { appendToolCall } from "../telemetry/turn-store";
import { recordActualCap } from "../core/ase";
import { DASHBOARD_PORT } from "../core/config";

// Extract task_id from Agent tool response — Claude Code returns it in several possible shapes
function extractTaskId(response: unknown): string | null {
  if (!response) return null;
  try {
    const obj: Record<string, unknown> = typeof response === "string" ? JSON.parse(response) : response as Record<string, unknown>;
    return (obj.task_id ?? obj.id ?? obj.taskId ?? null) as string | null;
  } catch { return null; }
}

interface PostToolPayload {
  session_id?: string;
  tool_name?: string;
  tool_input?: Record<string, unknown>;
  tool_response?: unknown;
  hook_event_name?: string;
}

// Sanitize tool_input — never log credential values
const REDACT_KEYS = new Set(["password", "token", "secret", "api_key", "key", "credential", "auth"]);

function sanitizeInput(input: Record<string, unknown> | undefined): Record<string, unknown> {
  if (!input) return {};
  return Object.fromEntries(
    Object.entries(input).map(([k, v]) => [
      k,
      REDACT_KEYS.has(k.toLowerCase()) ? "[REDACTED]" : v,
    ])
  );
}

function sessionsDir(): string {
  const dir = join(getAegisDir(), "sessions");
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  return dir;
}

// ─── session_mask bit-transition (BMC-003 / BMC-006) ─────────────────────────
// Maps file-path patterns to session_mask bit positions.
// Bit 0 (1) = core-invariants — always on, never matched here.
// Bit 7 (128) = session-close — set by session-end / dream-phase.

const SESSION_MASK_BITS: Array<[number, RegExp]> = [
  [  2, /\/codex\.json$|\/proposals\/|\/ankr-todos\//],        // bit 1: new-service
  [  4, /\/prisma\/|\/migrations\/|schema\.prisma$|databases\.json$/], // bit 2: db-ops
  [  8, /\/proposals\/|\/ankr-todos\//],                        // bit 3: knowledge-docs
  [ 16, /\/forja\/|\/services\.json$|services\.json$/],         // bit 4: design-laws
  [ 32, /mari8x|ankr-maritime|ankrgrid-maritime|liner8x|mpv8x|feeder8x|watch8x|ship8x/i], // bit 5: maritime
  [ 64, /\/chetna\/|\/jaal[\./]|superdomain|ankr-ai-gateway/],  // bit 6: agi-layer
];

// @rule:BMC-003 bits are append-only within a session — never cleared mid-session
// @rule:NFR-002 atomic write via tmp-then-rename
function updateSessionMask(filePath: string): void {
  const maskFile = join(getAegisDir(), "current_session_mask");
  try {
    const current = existsSync(maskFile)
      ? parseInt(readFileSync(maskFile, "utf-8").trim(), 10) || 1
      : 1;

    let updated = current;
    for (const [bit, pattern] of SESSION_MASK_BITS) {
      if (pattern.test(filePath)) updated |= bit;
    }

    if (updated !== current) {
      const tmp = maskFile + ".tmp";
      writeFileSync(tmp, String(updated), { mode: 0o600 });
      renameSync(tmp, maskFile);
      // Emit to stderr for observability only — never block tool execution
      process.stderr.write(`[KAVACH:mask] session_mask ${current}→${updated} (touched: ${filePath.split("/").slice(-2).join("/")})\n`);
    }
  } catch { /* never block tool execution */ }
}

// Extract the primary file path from tool input (Read / Edit / Write)
function extractFilePath(toolName: string, input: Record<string, unknown>): string | null {
  if (toolName === "Read" || toolName === "Edit" || toolName === "Write") {
    return typeof input.file_path === "string" ? input.file_path : null;
  }
  return null;
}

// @rule:KOS-077
function run(): void {
  const stdin = (() => {
    try { return readFileSync("/dev/stdin", "utf-8"); } catch { return "{}"; }
  })();

  let payload: PostToolPayload = {};
  try { payload = JSON.parse(stdin); } catch {}

  // Claude Code v2.1+ does not inject session_id in hook payloads — read from state file
  const currentSessionFile = join(getAegisDir(), "current_session");
  const storedSessionId = existsSync(currentSessionFile)
    ? readFileSync(currentSessionFile, "utf-8").trim()
    : null;
  const sessionId = payload.session_id ?? process.env.CLAUDE_SESSION_ID ?? storedSessionId ?? "unknown";
  const toolName = payload.tool_name ?? "unknown";
  const now = new Date().toISOString();

  // Extract a short summary from tool_response for the log
  // Full response is NOT stored — just outcome signal (success/error + first 200 chars)
  let outcome: "success" | "error" = "success";
  let responseSummary: string | null = null;
  try {
    const resp = payload.tool_response;
    if (typeof resp === "string") {
      if (resp.toLowerCase().includes("error") || resp.toLowerCase().includes("failed")) {
        outcome = "error";
      }
      responseSummary = resp.slice(0, 200);
    } else if (typeof resp === "object" && resp !== null) {
      const respStr = JSON.stringify(resp);
      if (respStr.toLowerCase().includes("error")) outcome = "error";
      responseSummary = respStr.slice(0, 200);
    }
  } catch {}

  const record = {
    ts: now,
    session_id: sessionId,
    tool: toolName,
    input: sanitizeInput(payload.tool_input),
    outcome,
    response_preview: responseSummary,
  };

  // Append to per-session JSONL — one line per tool call
  // JSONL = newline-delimited JSON = offline-verifiable, grep-able, no DB lock
  const logPath = join(sessionsDir(), `${sessionId}.jsonl`);
  try {
    appendFileSync(logPath, JSON.stringify(record) + "\n");
  } catch { /* never block tool execution */ }

  // @rule:BMC-003 update session_mask when file-touching tools fire
  const filePath = extractFilePath(toolName, payload.tool_input ?? {});
  if (filePath) updateSessionMask(filePath);

  // @rule:KOS-091 — append tool call to the current open turn for OTLP span assembly
  try {
    appendToolCall(sessionId, {
      name:          toolName,
      started_at:    now,
      input_preview: JSON.stringify(sanitizeInput(payload.tool_input)).slice(0, 200),
    });
  } catch { /* never block tool execution */ }

  // Increment tool_call_count in sessions table
  try {
    getDb().run(
      "UPDATE sessions SET tool_call_count = COALESCE(tool_call_count,0) + 1, last_activity=? WHERE session_id=?",
      [now, sessionId]
    );
  } catch {}

  // @rule:ASE-006 @rule:ASE-003 — record tool as actual_cap used; update ASE budget estimate
  // The ASE session tracks actual_caps_used for drift detection (actual \ declared).
  const aseSessionFile = join(getAegisDir(), "ase_session_id");
  const aseSessionId = existsSync(aseSessionFile)
    ? readFileSync(aseSessionFile, "utf-8").trim()
    : null;
  if (aseSessionId) {
    try {
      // Record tool name as a capability used (cap = tool name, normalized)
      recordActualCap(aseSessionId, toolName);
    } catch {}
    // Update budget via Aegis API — token cost comes from usage_in hook payload if available
    try {
      const usageIn = (payload as any).usage;
      if (usageIn && typeof usageIn === "object") {
        const inputT = Number((usageIn as any).input_tokens ?? 0);
        const outputT = Number((usageIn as any).output_tokens ?? 0);
        const cacheRead = Number((usageIn as any).cache_read_input_tokens ?? 0);
        const cacheCreate = Number((usageIn as any).cache_creation_input_tokens ?? 0);
        // Rough claude-sonnet pricing: $3/1M input, $15/1M output, $0.30/1M cache_read
        const costEst = (inputT * 3 + outputT * 15 + cacheRead * 0.3 + cacheCreate * 3.75) / 1_000_000;
        if (costEst > 0) {
          const AEGIS_URL = process.env.AEGIS_URL ?? `http://localhost:${DASHBOARD_PORT}`;
          // fire-and-forget — never block tool execution
          fetch(`${AEGIS_URL}/api/v1/aegis/session/${encodeURIComponent(aseSessionId)}/usage`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ cost_usd_estimate: costEst, cap_used: toolName }),
          }).catch(() => {});
        }
      }
    } catch {}
  }

  // @rule:KOS-T095 — capture task_id from Agent tool response (arrives here at spawn time)
  // The Notification hook uses task_id to mark the specific agent complete when it finishes.
  if (toolName === "Agent") {
    const taskId = extractTaskId(payload.tool_response);
    if (taskId) {
      try {
        // Update most recent background_agents row for this session that has no task_id yet
        getDb().run(
          "UPDATE background_agents SET task_id=? WHERE session_id=? AND task_id IS NULL AND status='running' ORDER BY id DESC LIMIT 1",
          [taskId, sessionId]
        );
      } catch {}
    }
  }

}

run();
process.exit(0);
