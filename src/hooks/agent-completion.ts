// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// agent-completion — Notification hook
// Fires when Claude Code receives a notification — including background agent completion.
// This is the correct signal: PostToolUse fires at spawn (too early), Notification fires at done.
//
// @rule:KOS-T095 background agent guard — auto-clear when completion notification arrives

import { readFileSync, existsSync } from "fs";
import { join } from "path";
import { getAegisDir } from "../core/config";
import { acknowledgeAllBgAgents, completeBgAgent } from "../core/db";

interface NotificationPayload {
  session_id?: string;
  message?: string;
  title?: string;
  hook_event_name?: string;
  task_id?: string;         // present when notification is a background agent completion
}

function run(): void {
  const stdin = (() => {
    try { return readFileSync("/dev/stdin", "utf-8"); } catch { return "{}"; }
  })();

  let payload: NotificationPayload = {};
  try { payload = JSON.parse(stdin); } catch {}

  const currentSessionFile = join(getAegisDir(), "current_session");
  const storedSessionId = existsSync(currentSessionFile)
    ? readFileSync(currentSessionFile, "utf-8").trim()
    : null;
  const sessionId = payload.session_id ?? process.env.CLAUDE_SESSION_ID ?? storedSessionId ?? "unknown";

  const msg = (payload.message ?? payload.title ?? "").toLowerCase();

  // Background agent completion notifications contain phrases like:
  //   "agent completed", "background task", "task finished", "agent finished"
  // Claude Code does not use a structured type field — match on text.
  const taskId = payload.task_id;

  if (taskId) {
    // Precise: task_id present → mark exactly that agent complete
    try {
      completeBgAgent(taskId);
      process.stderr.write(`[KAVACH:bg] agent ${taskId} completed — guard updated\n`);
    } catch {}
  } else {
    // Fallback: text-match for agent completion notification, bulk-acknowledge session
    const isAgentCompletion =
      msg.includes("agent") && (
        msg.includes("complet") ||
        msg.includes("finish") ||
        msg.includes("done") ||
        msg.includes("result")
      );
    if (isAgentCompletion) {
      try {
        acknowledgeAllBgAgents(sessionId);
        process.stderr.write(`[KAVACH:bg] background agent completion detected (text match) — guard cleared\n`);
      } catch {}
    }
  }
}

run();
process.exit(0);
