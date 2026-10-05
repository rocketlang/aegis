// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// What a hook is told: its input, and whose call it is.
//
// @rule:KAV-100 — a hook learns the session from the payload the harness sends it. A check
//                 that is kept per session (a spawn limit, a cap, a stop request) and looked
//                 up under the wrong name is a check that never runs.
//
// Two facts about a harness, both learned the hard way:
//   - a hook's stdin is a SOCKET. Opening the /dev/stdin path fails on a socket (ENXIO) and
//     the hook reads nothing; reading file descriptor 0 reads it. (Fixed in check-shield and
//     check-destructive on 2026-09-29; check-spawn kept the old read until 2.6.0.)
//   - the session id is IN THE PAYLOAD (`session_id`). No `CLAUDE_SESSION_ID` variable is
//     set. Until 2.6.0 check-budget and check-spawn read only that variable, so every
//     per-session check ran against a session called "unknown".

import { readFileSync } from "fs";
import { basename } from "path";

export interface HookInput {
  /** The input as received; "" when there was none. */
  raw: string;
  /** The payload when the input was a JSON object, otherwise null. */
  payload: Record<string, unknown> | null;
  /** The session this call belongs to, or "unknown". */
  sessionId: string;
  /** The agent making the call: a subagent's own id when the harness gives one, else the session. */
  agentId: string;
}

const usable = (v: unknown): v is string => typeof v === "string" && v.length > 0 && v.length <= 200 && !/[\0\n\r/\\]/.test(v);

/** Read the hook's input once. Never throws, and never waits on a terminal. */
export function readHookInput(): HookInput {
  let raw = "";
  if (!process.stdin.isTTY) {
    try { raw = readFileSync(0, "utf-8"); } catch { raw = ""; }
  }
  let payload: Record<string, unknown> | null = null;
  const text = raw.trim();
  if (text) {
    try {
      const v: unknown = JSON.parse(text);
      if (v !== null && typeof v === "object" && !Array.isArray(v)) payload = v as Record<string, unknown>;
    } catch { /* not JSON: the caller decides what that means */ }
  }
  return { raw: text, payload, ...whoIsCalling(payload) };
}

/**
 * The session and the agent, from the payload first. The environment is read after it, for
 * a harness or a script that does set a variable; `transcript_path` (its file is named for
 * the session) is the last source.
 */
export function whoIsCalling(payload: Record<string, unknown> | null, env: Record<string, string | undefined> = process.env): { sessionId: string; agentId: string } {
  const fromTranscript = typeof payload?.transcript_path === "string" ? basename(payload.transcript_path).replace(/\.jsonl$/, "") : "";
  const sessionId =
    [payload?.session_id, env.CLAUDE_SESSION_ID, env.CLAUDE_CODE_SESSION_ID, fromTranscript].find(usable) ?? "unknown";
  const agentId = [payload?.agent_id, env.CLAUDE_AGENT_ID].find(usable) ?? sessionId;
  return { sessionId, agentId };
}
