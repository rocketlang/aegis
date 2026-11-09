// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// `aegis gate-serve --gates <table.json> [--socket /run/aegis-gates/gate.sock] [--log <file.jsonl>]`
//
// Runs the gate runner (src/gate/runner.ts): the hooks' checks run here, as this process's user, on
// behalf of aegis-gate-client. Meant to run under its own system user from a unit the founder
// installs; HOME is that user's home, so the gates' state lives there and not in the session's.
// Exit: 1 bad arguments · 3 broke. Runs until stopped.

import { appendFileSync, existsSync, unlinkSync, chmodSync } from "fs";
import { homedir } from "os";
import { loadTable, serve } from "../../gate/runner";

export default async function gateServe(args: string[]): Promise<number> {
  const arg = (k: string) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : undefined; };
  const tablePath = arg("--gates");
  const socket = arg("--socket") ?? "/run/aegis-gates/gate.sock";
  const logPath = arg("--log");
  if (!tablePath) { console.error("gate-serve: --gates <table.json> is required"); return 1; }
  let table;
  try { table = loadTable(tablePath); } catch (e: any) { console.error(`gate-serve: ${e.message}`); return 1; }
  if (existsSync(socket)) unlinkSync(socket); // a stale socket from a previous run
  const home = process.env.HOME || homedir();
  const log = logPath ? (row: Record<string, unknown>) => { try { appendFileSync(logPath, JSON.stringify(row) + "\n"); } catch {} } : undefined;
  serve({ socket, table, home, log });
  chmodSync(socket, 0o660); // the agent's group connects; nobody else
  console.log(`gate-serve: ${Object.keys(table).length} gate(s) on ${socket}, home ${home}`);
  await new Promise(() => {}); // run until stopped
  return 0;
}
