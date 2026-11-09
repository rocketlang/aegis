// SPDX-License-Identifier: AGPL-3.0-only
// The gate runner and its thin client (AOR-003, INF-AOR-001). Throwaway sockets and scripts under a temp dir.
import { describe, it, expect, beforeAll, afterAll } from "bun:test";
import { mkdtempSync, writeFileSync, rmSync, chmodSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { serve, loadTable, childEnv, childCwd, type GateTable } from "./runner";

const CLIENT = join(import.meta.dir, "../../bin/aegis-gate-client.mjs");
let dir: string, sock: string, server: ReturnType<typeof serve>;

function script(name: string, body: string): string {
  const p = join(dir, name);
  writeFileSync(p, `#!/usr/bin/env bash\n${body}\n`); chmodSync(p, 0o755);
  return p;
}

// Async on purpose: the server runs in this same process, so a synchronous spawn would starve it.
async function client(gate: string, input: object, env: Record<string, string> = {}, socket = sock) {
  const p = Bun.spawn(["node", CLIENT, gate], {
    stdin: new Blob([JSON.stringify(input)]), stdout: "pipe", stderr: "pipe",
    env: { PATH: process.env.PATH!, AEGIS_GATE_SOCK: socket, AEGIS_GATE_TIMEOUT_MS: "5000", ...env },
  });
  const [out, err, code] = await Promise.all([new Response(p.stdout).text(), new Response(p.stderr).text(), p.exited]);
  return { code, out, err };
}

const pre = { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "echo hi" } };
const post = { hook_event_name: "PostToolUse", tool_name: "Bash" };

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "aegis-gate-"));
  sock = join(dir, "gate.sock");
  const table: GateTable = {
    pass: { argv: [script("pass.sh", 'cat >/dev/null; echo "passed"; exit 0')] },
    block: { argv: [script("block.sh", 'cat >/dev/null; echo "no, refused" >&2; exit 2')] },
    echo: { argv: [script("echo.sh", "cat")] },
    env: { argv: [script("env.sh", 'cat >/dev/null; echo "C=${CLAUDE_PROJECT_DIR:-none} S=${SECRET_X:-none} P=${ANKR_HOOK_CLAUDE_PID:-none} H=$HOME"; pwd')] },
    slow: { argv: [script("slow.sh", "cat >/dev/null; sleep 5; exit 0")], timeoutMs: 300 },
  };
  server = serve({ socket: sock, table, home: dir });
});
afterAll(() => { server.stop(true); rmSync(dir, { recursive: true, force: true }); });

describe("gate runner + client", () => {
  it("AOR-G01: a passing gate passes its output and code through", async () => {
    const r = await client("pass", pre);
    expect(r.code).toBe(0); expect(r.out).toContain("passed");
  });
  it("AOR-G02: a refusing gate's exit 2 and stderr reach the hook", async () => {
    const r = await client("block", pre);
    expect(r.code).toBe(2); expect(r.err).toContain("no, refused");
  });
  it("AOR-G03: the hook input reaches the gate unchanged", async () => {
    const r = await client("echo", pre);
    expect(JSON.parse(r.out)).toEqual(pre);
  });
  it("AOR-G04: only CLAUDE_* variables cross; the Claude pid is passed; HOME is the runner's", async () => {
    const r = await client("env", pre, { CLAUDE_PROJECT_DIR: "/root/x", SECRET_X: "leak" });
    expect(r.out).toContain("C=/root/x"); expect(r.out).toContain("S=none");
    expect(r.out).toMatch(/P=\d+/); expect(r.out).toContain(`H=${dir}`);
  });
  it("AOR-G05: an unknown gate name is refused", async () => {
    const r = await client("nosuch", pre);
    expect(r.code).toBe(2); expect(r.err).toContain('no gate named "nosuch"');
  });
  it("AOR-G06: a gate past its timeout is stopped and counts as a refusal", async () => {
    const r = await client("slow", pre);
    expect(r.code).toBe(2); expect(r.err).toContain("treated as a refusal");
  });
  it("INF-AOR-001: no runner → PreToolUse is BLOCKED (fail closed)", async () => {
    const r = await client("pass", pre, {}, join(dir, "absent.sock"));
    expect(r.code).toBe(2); expect(r.err).toContain("BLOCKED");
  });
  it("INF-AOR-001: no runner → other events pass with a warning", async () => {
    const r = await client("pass", post, {}, join(dir, "absent.sock"));
    expect(r.code).toBe(0); expect(r.err).toContain("warning");
  });
  it("AOR-G07: a malformed gate name never leaves the client", async () => {
    const r = await client("../etc/passwd", pre);
    expect(r.code).toBe(2);
  });
});

describe("gate table and child setup", () => {
  it("AOR-G08: the table refuses relative commands and bad names", () => {
    const p = join(dir, "t.json");
    writeFileSync(p, JSON.stringify({ ok: { argv: ["bin/x"] } }));
    expect(() => loadTable(p)).toThrow(/absolute/);
    writeFileSync(p, JSON.stringify({ "Bad Name": { argv: ["/bin/true"] } }));
    expect(() => loadTable(p)).toThrow(/name/);
  });
  it("AOR-G09: env filter and cwd fallback", () => {
    const e = childEnv({ v: 1, gate: "x", stdin: "", env: { CLAUDE_A: "1", PATH: "/evil", LD_PRELOAD: "/x.so" }, claude_pid: 42 }, "/h");
    expect(e.CLAUDE_A).toBe("1"); expect(e.LD_PRELOAD).toBeUndefined(); expect(e.PATH).not.toBe("/evil"); expect(e.ANKR_HOOK_CLAUDE_PID).toBe("42");
    expect(childCwd("relative/dir", "/h")).toBe("/h"); expect(childCwd("/no/such/dir/x", "/h")).toBe("/h"); expect(childCwd("/tmp", "/h")).toBe("/tmp");
  });
});
