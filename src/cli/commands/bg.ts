// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// aegis bg — background agent guard management
// @rule:KOS-T095 background agent guard

import { getDb, acknowledgeAllBgAgents, getUnacknowledgedBgAgents } from "../../core/db";
import { existsSync, readFileSync } from "fs";
import { join } from "path";
import { getAegisDir } from "../../core/config";

export default async function bg(args: string[]): Promise<void> {
  const subcommand = args[0] ?? "list";

  const currentSessionFile = join(getAegisDir(), "current_session");
  const sessionId = existsSync(currentSessionFile)
    ? readFileSync(currentSessionFile, "utf-8").trim()
    : process.env.CLAUDE_SESSION_ID ?? "unknown";

  if (subcommand === "list") {
    const pending = getUnacknowledgedBgAgents(sessionId, 90);
    if (pending.length === 0) {
      console.log("No unacknowledged background agents for this session.");
      return;
    }
    console.log(`\nBackground agents (session: ${sessionId}):\n`);
    for (const a of pending) {
      const age = Math.round((Date.now() - new Date(a.spawned_at).getTime()) / 60000);
      const desc = a.description ?? a.subagent_type ?? "unnamed";
      console.log(`  [${a.id}] ${desc} — spawned ${age}m ago`);
    }
    console.log(`\nRun 'aegis bg ack' when agents are done to allow session exit.\n`);
    return;
  }

  if (subcommand === "ack") {
    acknowledgeAllBgAgents(sessionId);
    console.log(`[AEGIS:bg] All background agents acknowledged — Stop guard cleared for session ${sessionId}`);
    return;
  }

  console.error(`Unknown bg subcommand: ${subcommand}. Use 'bg list' or 'bg ack'.`);
  process.exit(1);
}
