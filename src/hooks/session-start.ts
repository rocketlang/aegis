// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// session-start — UserPromptSubmit hook
// Fires on every user prompt. First fire per session = session registration.
// Captures the DESK: hostname, cwd, git remote, model, Claude Code version.
//
// @rule:KOS-076 every Claude Code session auto-registers at first prompt;
//               desk context (hostname/cwd/git/model) is the audit anchor
//
// Records to:
//   ~/.aegis/aegis.db  sessions table  (structured, queryable)
//   ~/.aegis/sessions/{session_id}.desk.json  (self-contained, offline-verifiable)

import { readFileSync, writeFileSync, existsSync, mkdirSync } from "fs";
import { join } from "path";
import { hostname } from "os";
import { execSync } from "child_process";
import { getAegisDir } from "../core/config";
import { getDb, acknowledgeAllBgAgents } from "../core/db";
import { issueMudrika, loadOrRotateMudrika } from "../kernel/mudrika";

interface HookPayload {
  session_id?: string;
  cwd?: string;
  transcript_path?: string;
  hook_event_name?: string;
  prompt?: string;
}

interface DeskContext {
  session_id: string;
  registered_at: string;
  hostname: string;
  cwd: string;
  git_remote: string | null;
  git_branch: string | null;
  git_repo: string | null;
  model: string | null;
  claude_code_version: string | null;
  transcript_path: string | null;
  rule_ref: "KOS-076";
}

function tryExec(cmd: string): string | null {
  try {
    return execSync(cmd, { encoding: "utf-8", timeout: 2000, stdio: ["pipe","pipe","pipe"] }).trim() || null;
  } catch {
    return null;
  }
}

function sessionsDir(): string {
  const dir = join(getAegisDir(), "sessions");
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  return dir;
}

function deskPath(sessionId: string): string {
  return join(sessionsDir(), `${sessionId}.desk.json`);
}

// @rule:KOS-076
function run(): void {
  const stdin = (() => {
    try { return readFileSync("/dev/stdin", "utf-8"); } catch { return "{}"; }
  })();

  let payload: HookPayload = {};
  try { payload = JSON.parse(stdin); } catch {}

  // Claude Code v2.1+ does not inject session_id — derive a stable ID for the session lifetime.
  // Priority: payload > env > state file (reuse if desk exists) > fresh timestamp
  const currentSessionFile = join(getAegisDir(), "current_session");
  const storedId = existsSync(currentSessionFile)
    ? readFileSync(currentSessionFile, "utf-8").trim()
    : null;
  const sessionId =
    payload.session_id ??
    process.env.CLAUDE_SESSION_ID ??
    (storedId && existsSync(deskPath(storedId)) ? storedId : null) ??
    `ses_${Date.now()}`;
  const cwd = payload.cwd ?? process.cwd();

  // @rule:KOS-T095 — "force quit" escape: user types it when Stop hook blocks on bg agents
  const prompt = payload.prompt ?? "";
  if (/\bforce\s*quit\b/i.test(prompt)) {
    try {
      acknowledgeAllBgAgents(sessionId);
      process.stderr.write(`[KAVACH:bg] force quit — background agent guard cleared. Ctrl+C now to exit.\n`);
    } catch {}
  }

  // Only register once per session — subsequent prompts are already captured
  if (existsSync(deskPath(sessionId))) return;

  const now = new Date().toISOString();

  // Capture desk context
  const gitRemote = tryExec("git remote get-url origin");
  const gitBranch = tryExec("git rev-parse --abbrev-ref HEAD");
  const gitRepo = tryExec("git rev-parse --show-toplevel");
  const model =
    process.env.ANTHROPIC_MODEL ??
    process.env.CLAUDE_MODEL ??
    process.env.CLAUDE_CODE_MODEL ??
    null;
  const claudeVersion = tryExec("claude --version 2>/dev/null");

  const desk: DeskContext = {
    session_id: sessionId,
    registered_at: now,
    hostname: hostname(),
    cwd,
    git_remote: gitRemote,
    git_branch: gitBranch,
    git_repo: gitRepo,
    model,
    claude_code_version: claudeVersion,
    transcript_path: payload.transcript_path ?? null,
    rule_ref: "KOS-076",
  };

  // Write desk file — self-contained, offline-verifiable per session
  writeFileSync(deskPath(sessionId), JSON.stringify(desk, null, 2), { mode: 0o600 });

  // Persist session ID so PostToolUse + Stop hooks can correlate without payload
  writeFileSync(join(getAegisDir(), "current_session"), sessionId, { mode: 0o600 });

  // Register in sessions table
  try {
    const db = getDb();
    const existing = db.query("SELECT session_id FROM sessions WHERE session_id = ?").get(sessionId);
    if (existing) {
      db.run(
        `UPDATE sessions SET hostname=?, model=?, git_remote=?, project_path=? WHERE session_id=?`,
        [desk.hostname, desk.model ?? null, desk.git_remote ?? null, cwd, sessionId]
      );
    } else {
      db.run(
        `INSERT INTO sessions (session_id, project_path, first_seen, last_activity, status, hostname, model, git_remote)
         VALUES (?,?,?,?,'active',?,?,?)`,
        [sessionId, cwd, now, now, desk.hostname, desk.model ?? null, desk.git_remote ?? null]
      );
    }
  } catch { /* desk file is the fallback */ }

  // Issue mudrika for this session if not present
  try {
    const existing = loadOrRotateMudrika(sessionId);
    if (!existing) {
      const domain = process.env.KAVACHOS_DOMAIN ?? "general";
      const cred = issueMudrika(sessionId, sessionId, domain);
      try {
        getDb().run("UPDATE sessions SET mudrika_uri=? WHERE session_id=?", [cred.uri, sessionId]);
      } catch {}
    }
  } catch { /* mudrika optional at session start */ }

  process.stderr.write(
    `[KAVACH:session] registered ${sessionId} | host=${desk.hostname} | model=${desk.model ?? "unknown"} | cwd=${cwd}\n`
  );
}

run();
process.exit(0);
