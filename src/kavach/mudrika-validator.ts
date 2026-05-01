// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// @rule:KOS-062 proxy validates mudrika on every request; no valid mudrika = deny
//
// Hook-level guard: call assertMudrika(agentId) at the top of every PreToolUse hook.
// If mudrika is absent or invalid → exit(2) blocks the tool call before it executes.

import { checkMudrikaValid } from "../kernel/mudrika";

// @rule:KOS-062
export function assertMudrika(agentId: string): void {
  const { valid, reason } = checkMudrikaValid(agentId);
  if (!valid) {
    console.error(`[KAVACH] mudrika denied: ${agentId} — ${reason ?? "no credential"}`);
    process.exit(2);
  }
}

// Non-fatal variant — returns result for callers that want to log vs hard-stop
export function checkMudrika(agentId: string): { valid: boolean; reason?: string } {
  return checkMudrikaValid(agentId);
}
