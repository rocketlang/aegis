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

import { readFileSync, appendFileSync, existsSync, mkdirSync } from "fs";
import { join } from "path";
import { getAegisDir } from "../core/config";
import { getDb } from "../core/db";

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

  // Increment tool_call_count in sessions table
  try {
    getDb().run(
      "UPDATE sessions SET tool_call_count = COALESCE(tool_call_count,0) + 1, last_activity=? WHERE session_id=?",
      [now, sessionId]
    );
  } catch {}

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
