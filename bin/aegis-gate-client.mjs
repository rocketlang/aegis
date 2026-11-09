#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// aegis-gate-client <gate> — the thin hook client of the gate runner (AOR-003, INF-AOR-001).
// Claude Code runs this as the hook. It forwards the hook's input, its cwd, the CLAUDE_* variables
// and its parent pid (the Claude process) to the runner, prints what the runner printed and exits
// with the runner's code. It never sends a command line, only a gate name.
//
// Fail closed: if the runner cannot be reached or does not answer in time, a PreToolUse hook exits 2
// (the tool call is blocked); any other event exits 0 with a warning, because blocking it blocks nothing.
//
// Env: AEGIS_GATE_SOCK (default /run/aegis-gates/gate.sock) · AEGIS_GATE_TIMEOUT_MS (default 90000)
import net from "node:net";
import { readFileSync } from "node:fs";

const gate = process.argv[2];
const SOCK = process.env.AEGIS_GATE_SOCK || "/run/aegis-gates/gate.sock";
const TIMEOUT = Number(process.env.AEGIS_GATE_TIMEOUT_MS) || 90_000;

let stdin = "";
try { stdin = readFileSync(0, "utf8"); } catch { stdin = ""; }
let event = "";
try { event = JSON.parse(stdin || "{}").hook_event_name || ""; } catch {}
const blocking = event === "PreToolUse";

function unreachable(why) {
  if (blocking) {
    process.stderr.write(`[AEGIS-GATE] BLOCKED: the gate runner did not answer (${why}). A check that cannot run refuses (INF-AOR-001).\n`);
    process.exit(2);
  }
  process.stderr.write(`[AEGIS-GATE] warning: the gate runner did not answer (${why}); ${event || "this"} hook skipped.\n`);
  process.exit(0);
}

if (!gate || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(gate)) unreachable("no valid gate name given");

const env = {};
for (const [k, v] of Object.entries(process.env)) if (/^CLAUDE_[A-Z0-9_]*$/.test(k) && typeof v === "string") env[k] = v;
const req = JSON.stringify({ v: 1, gate, stdin, cwd: process.cwd(), env, claude_pid: process.ppid }) + "\n";

let buf = "";
let settled = false;
const sock = net.createConnection(SOCK);
const timer = setTimeout(() => { if (!settled) { settled = true; sock.destroy(); unreachable(`no answer within ${TIMEOUT} ms`); } }, TIMEOUT);
sock.on("connect", () => sock.write(req));
sock.on("data", (d) => { buf += d.toString("utf8"); });
sock.on("error", (e) => { if (!settled) { settled = true; clearTimeout(timer); unreachable(e.code || e.message); } });
sock.on("close", () => {
  if (settled) return;
  settled = true; clearTimeout(timer);
  let res;
  try { res = JSON.parse(buf.split("\n")[0]); } catch { return unreachable("the answer was not readable"); }
  if (res?.v !== 1 || !Number.isInteger(res.code)) return unreachable("the answer was not in the expected form");
  if (res.stdout) process.stdout.write(res.stdout);
  if (res.stderr) process.stderr.write(res.stderr);
  process.exit(res.code);
});
