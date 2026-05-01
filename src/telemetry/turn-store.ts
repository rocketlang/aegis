// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// @rule:KOS-091 turn state persistence — one row per user-prompt → response cycle
//
// Hooks are short-lived processes — state crosses invocations via SQLite.
// Schema is additive (CREATE IF NOT EXISTS) — safe to call from any hook.

import { Database } from "bun:sqlite";
import { createHash, randomBytes } from "crypto";
import { join } from "path";
import { getAegisDir } from "../core/config";

// ── Types ──────────────────────────────────────────────────────────────────────

export interface ToolCallEntry {
  name: string;
  started_at: string;
  ended_at?: string;
  input_preview: string;
}

export interface LlmCallEntry {
  model: string;
  input_tokens: number;
  output_tokens: number;
  cost_usd: number;
  timestamp: string;
}

export interface TurnRow {
  id: number;
  turn_id: string;
  trace_id: string;
  session_id: string;
  turn_number: number;
  started_at: string;
  ended_at: string | null;
  prompt_preview: string | null;
  tool_calls: string;   // JSON
  llm_calls: string;    // JSON
  exported: number;
}

// ── DB access ─────────────────────────────────────────────────────────────────

function openDb(): Database {
  const db = new Database(join(getAegisDir(), "aegis.db"), { create: true });
  db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;");
  db.exec(`
    CREATE TABLE IF NOT EXISTS otel_turns (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      turn_id       TEXT NOT NULL UNIQUE,
      trace_id      TEXT NOT NULL,
      session_id    TEXT NOT NULL,
      turn_number   INTEGER NOT NULL DEFAULT 1,
      started_at    TEXT NOT NULL,
      ended_at      TEXT,
      prompt_preview TEXT,
      tool_calls    TEXT NOT NULL DEFAULT '[]',
      llm_calls     TEXT NOT NULL DEFAULT '[]',
      exported      INTEGER NOT NULL DEFAULT 0
    )
  `);
  return db;
}

// ── ID helpers ─────────────────────────────────────────────────────────────────

// trace_id: deterministic — all turns in a session share one trace
export function sessionTraceId(sessionId: string): string {
  return createHash("sha256").update("kavachos:" + sessionId).digest("hex").slice(0, 32);
}

// span_id: 16 random hex chars
export function newSpanId(): string {
  return randomBytes(8).toString("hex");
}

// ── CRUD ───────────────────────────────────────────────────────────────────────

// Called from session-start hook on every UserPromptSubmit
export function createTurn(sessionId: string, promptPreview: string | null): string {
  const db = openDb();
  const traceId = sessionTraceId(sessionId);
  const turnId = newSpanId();
  const now = new Date().toISOString();
  const prev = db.query(
    `SELECT MAX(turn_number) as n FROM otel_turns WHERE session_id = ?`
  ).get(sessionId) as { n: number | null } | null;
  const turnNumber = (prev?.n ?? 0) + 1;
  db.run(
    `INSERT OR IGNORE INTO otel_turns
       (turn_id, trace_id, session_id, turn_number, started_at, prompt_preview)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [turnId, traceId, sessionId, turnNumber, now, promptPreview]
  );
  return turnId;
}

// Called from session-activity (PostToolUse) hook
export function appendToolCall(sessionId: string, entry: ToolCallEntry): void {
  const db = openDb();
  const row = db.query(
    `SELECT id, tool_calls FROM otel_turns
     WHERE session_id = ? AND exported = 0 ORDER BY id DESC LIMIT 1`
  ).get(sessionId) as { id: number; tool_calls: string } | null;
  if (!row) return;
  const calls: ToolCallEntry[] = JSON.parse(row.tool_calls);
  calls.push(entry);
  db.run(`UPDATE otel_turns SET tool_calls = ? WHERE id = ?`,
    [JSON.stringify(calls), row.id]);
}

// Called from usage_log writer in monitor pipeline
export function appendLlmCall(sessionId: string, entry: LlmCallEntry): void {
  const db = openDb();
  const row = db.query(
    `SELECT id, llm_calls FROM otel_turns
     WHERE session_id = ? AND exported = 0 ORDER BY id DESC LIMIT 1`
  ).get(sessionId) as { id: number; llm_calls: string } | null;
  if (!row) return;
  const calls: LlmCallEntry[] = JSON.parse(row.llm_calls);
  calls.push(entry);
  db.run(`UPDATE otel_turns SET llm_calls = ? WHERE id = ?`,
    [JSON.stringify(calls), row.id]);
}

// Stamp ended_at on the current open turn (called at session-end before export)
export function closeTurn(sessionId: string): void {
  const db = openDb();
  db.run(
    `UPDATE otel_turns SET ended_at = ?
     WHERE session_id = ? AND ended_at IS NULL AND exported = 0`,
    [new Date().toISOString(), sessionId]
  );
}

// Returns all unexported turns for the session, ordered oldest first
export function getUnexportedTurns(sessionId: string): TurnRow[] {
  const db = openDb();
  return db.query(
    `SELECT * FROM otel_turns WHERE session_id = ? AND exported = 0 ORDER BY turn_number ASC`
  ).all(sessionId) as TurnRow[];
}

// Mark all turns for the session as exported (idempotent)
export function markExported(sessionId: string): void {
  const db = openDb();
  db.run(`UPDATE otel_turns SET exported = 1 WHERE session_id = ?`, [sessionId]);
}
