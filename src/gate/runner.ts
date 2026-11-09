// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// The gate runner (AOR-003, agent-out-of-reach P2, 2026-11-09).
//
// Claude Code runs every hook as the user the session runs as. A hook that writes the gates' record
// (refusals, mandates, shield rules) therefore needs write access the watched session would share.
// The runner moves the check out of the session's reach: it is a small daemon, running as its own
// user, that runs the SAME frozen hook commands on behalf of a thin client. The client sends a gate
// NAME and the hook's input; it never sends a command line. The runner owns the state.
//
// Protocol: one JSON line each way over a unix socket.
//   request  {v:1, gate, stdin, cwd, env:{CLAUDE_*...}, claude_pid}
//   response {v:1, code, stdout, stderr}
// A gate name not in the table is refused (code 2). A gate that runs past its timeout is killed
// and answered with code 2, so a PreToolUse check that hangs blocks instead of passing.

import { existsSync, statSync, readFileSync } from "fs";

export interface GateSpec { argv: string[]; timeoutMs?: number }
export type GateTable = Record<string, GateSpec>;

export interface GateRequest { v: 1; gate: string; stdin: string; cwd?: string; env?: Record<string, string>; claude_pid?: number }
export interface GateResponse { v: 1; code: number; stdout: string; stderr: string }

const MAX_REQUEST = 4 * 1024 * 1024; // a hook input carries a tool call; 4 MB is ample
const DEFAULT_TIMEOUT = 60_000;
const ENV_PASS = /^CLAUDE_[A-Z0-9_]*$/; // only Claude Code's own variables cross; never PATH, HOME, tokens

export function loadTable(path: string): GateTable {
  const raw = JSON.parse(readFileSync(path, "utf8"));
  const out: GateTable = {};
  for (const [name, spec] of Object.entries(raw as Record<string, any>)) {
    if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(name)) throw new Error(`gate name not allowed: ${name}`);
    if (!Array.isArray(spec?.argv) || !spec.argv.length || !spec.argv.every((a: unknown) => typeof a === "string"))
      throw new Error(`gate ${name}: argv must be a non-empty string array`);
    if (!spec.argv[0].startsWith("/")) throw new Error(`gate ${name}: argv[0] must be an absolute path`);
    out[name] = { argv: spec.argv, timeoutMs: Number.isInteger(spec.timeoutMs) ? spec.timeoutMs : undefined };
  }
  return out;
}

export function parseRequest(line: string): GateRequest | string {
  let r: any;
  try { r = JSON.parse(line); } catch { return "request is not JSON"; }
  if (r?.v !== 1) return "unknown protocol version";
  if (typeof r.gate !== "string") return "no gate named";
  if (typeof r.stdin !== "string") return "stdin must be a string";
  return r as GateRequest;
}

export function childEnv(req: GateRequest, home: string): Record<string, string> {
  const env: Record<string, string> = { PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/root/.bun/bin", HOME: home };
  for (const [k, v] of Object.entries(req.env ?? {})) if (ENV_PASS.test(k) && typeof v === "string") env[k] = v;
  if (Number.isInteger(req.claude_pid) && (req.claude_pid as number) > 1) env.ANKR_HOOK_CLAUDE_PID = String(req.claude_pid);
  return env;
}

export function childCwd(cwd: string | undefined, home: string): string {
  if (typeof cwd !== "string" || !cwd.startsWith("/")) return home;
  try { return existsSync(cwd) && statSync(cwd).isDirectory() ? cwd : home; } catch { return home; }
}

export async function runGate(table: GateTable, req: GateRequest, home: string): Promise<GateResponse> {
  const spec = table[req.gate];
  if (!spec) return { v: 1, code: 2, stdout: "", stderr: `[AEGIS-GATE] refused: no gate named "${req.gate}" in the runner's table\n` };
  const proc = Bun.spawn(spec.argv, {
    cwd: childCwd(req.cwd, home), env: childEnv(req, home),
    stdin: new Blob([req.stdin]), stdout: "pipe", stderr: "pipe",
  });
  const limit = spec.timeoutMs ?? DEFAULT_TIMEOUT;
  const finished = Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited]);
  let timer: ReturnType<typeof setTimeout> | undefined;
  // Race, not wait: a grandchild of the gate can hold its output pipe open after the gate itself is killed.
  const late = new Promise<"late">((r) => { timer = setTimeout(() => r("late"), limit); });
  const out = await Promise.race([finished, late]);
  clearTimeout(timer);
  if (out === "late") {
    proc.kill(9);
    return { v: 1, code: 2, stdout: "", stderr: `[AEGIS-GATE] gate "${req.gate}" ran past ${limit} ms and was stopped; treated as a refusal\n` };
  }
  const [stdout, stderr, code] = out;
  return { v: 1, code: code ?? 2, stdout, stderr };
}

export interface ServeOptions { socket: string; table: GateTable; home: string; log?: (row: Record<string, unknown>) => void }

export function serve(opts: ServeOptions) {
  return Bun.listen<{ buf: string; done: boolean }>({
    unix: opts.socket,
    socket: {
      open(s) { s.data = { buf: "", done: false }; },
      async data(s, chunk) {
        if (s.data.done) return;
        s.data.buf += Buffer.from(chunk).toString("utf8");
        if (s.data.buf.length > MAX_REQUEST) { s.data.done = true; s.end(JSON.stringify({ v: 1, code: 2, stdout: "", stderr: "[AEGIS-GATE] request too large; refused\n" }) + "\n"); return; }
        const nl = s.data.buf.indexOf("\n");
        if (nl < 0) return;
        s.data.done = true;
        const req = parseRequest(s.data.buf.slice(0, nl));
        let res: GateResponse;
        if (typeof req === "string") res = { v: 1, code: 2, stdout: "", stderr: `[AEGIS-GATE] refused: ${req}\n` };
        else {
          const t0 = Date.now();
          try { res = await runGate(opts.table, req, opts.home); }
          catch (e: any) { res = { v: 1, code: 2, stdout: "", stderr: `[AEGIS-GATE] gate failed to run (${e?.message ?? e}); treated as a refusal\n` }; }
          opts.log?.({ ts: new Date().toISOString(), gate: req.gate, code: res.code, ms: Date.now() - t0, claude_pid: req.claude_pid ?? null });
        }
        s.end(JSON.stringify(res) + "\n");
      },
    },
  });
}
