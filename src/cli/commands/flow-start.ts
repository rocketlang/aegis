// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// aegis flow-start — Claude Code SessionStart hook (governed-turn-protocol §19).
//
// At every session start or resume: keep, issue or renew the session's mandate (never replace a revoked
// one), and request the session's own root envelope naming it. Prints nothing on stdout (a SessionStart
// hook's stdout becomes part of the session's context); one line on stderr. Never stops a session: exit 0.

import { readFileSync } from "fs";
import { DASHBOARD_PORT, loadConfig } from "../../core/config";
import { startFlow } from "../../kavach/flow-start";

export default async function flowStart(): Promise<void> {
  let input: Record<string, unknown> = {};
  try { input = JSON.parse(readFileSync(0, "utf8") || "{}"); } catch { /* fd 0: stdin may be a socket */ }
  let returnProof: unknown;
  try { returnProof = (loadConfig().kavach as { mandate_return_proof?: unknown } | undefined)?.mandate_return_proof; } catch { /* defaults */ }
  const { note } = await startFlow(input, {
    aegisUrl: process.env.AEGIS_URL ?? `http://localhost:${DASHBOARD_PORT}`, returnProof,
    flowEnv: process.env.AEGIS_FLOW, envFile: process.env.CLAUDE_ENV_FILE,
  });
  process.stderr.write(`[flow-start] ${note}\n`);
  process.exit(0);
}
