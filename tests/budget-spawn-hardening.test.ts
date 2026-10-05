// SPDX-License-Identifier: AGPL-3.0-only
// check-budget and check-spawn, driven the way a harness drives them (2.6.0): stdin is a
// SOCKET (tests/helpers/run-hook-on-socket.py) and the session id is in the payload.
//
// What these pin:
//   §B1 who is calling  (KAV-100) the session comes from the payload, then the environment
//   §B2 budget          per-agent cap seen for the payload's session; a spent week warns
//   §B3 spawn           the delegation check runs on a socket; per-session limits are seen
//   §B4 held            the Level 0 valve check runs only when it is switched on
//   §B5 said so         a call not checked, or checked on the defaults, says so
//   §B6 limits          what these hooks do NOT do
//
// Each case has its own throwaway HOME. Run with the network cut: unshare -n bun test <file>
import { describe, it, expect } from "bun:test";
import { mkdirSync, mkdtempSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { whoIsCalling } from "../src/cli/hook-input";

const ROOT = process.env.AEGIS_TEST_ROOT || join(import.meta.dir, "..");
const HELPER = join(import.meta.dir, "helpers/run-hook-on-socket.py");
const CLI = join(ROOT, "src/cli/index.ts");
const S = "sess-abc";

function home(config: Record<string, unknown> = {}): string {
  const h = mkdtempSync(join(tmpdir(), "aegis-budget-spawn-"));
  mkdirSync(join(h, ".aegis"), { recursive: true });
  if (Object.keys(config).length) writeFileSync(join(h, ".aegis/config.json"), JSON.stringify(config));
  return h;
}
const ENFORCE = { enforcement: { mode: "enforce" } };
const envOf = (h: string, extra: Record<string, string> = {}) => {
  const e: Record<string, string | undefined> = { ...process.env, HOME: h, AEGIS_HOME: "", ANKR_CONFIG_DIR: join(h, "none"), ...extra };
  for (const k of ["CLAUDE_SESSION_ID", "CLAUDE_CODE_SESSION_ID", "CLAUDE_AGENT_ID"]) if (!(k in extra)) delete e[k];
  return e as Record<string, string>;
};
function hook(h: string, name: "check-budget" | "check-spawn", payload: unknown, extra: Record<string, string> = {}): { exit: number; stderr: string } {
  const r = Bun.spawnSync(["python3", HELPER, ROOT, name], { stdin: Buffer.from(typeof payload === "string" ? payload : JSON.stringify(payload)), env: envOf(h, extra) });
  if (r.exitCode !== 0) throw new Error(`socket helper broke (exit ${r.exitCode}): ${r.stderr.toString()}`);
  return JSON.parse(r.stdout.toString());
}
/** State as the product's own monitor and commands would leave it. */
function seed(h: string, js: string): void {
  const r = Bun.spawnSync(["bun", "-e", `const db = await import(${JSON.stringify(join(ROOT, "src/core/db.ts"))}); ${js}`], { env: envOf(h) });
  if (r.exitCode !== 0) throw new Error("seed failed: " + r.stderr.toString().slice(0, 300));
}
function agent(h: string, id: string, sql: string): void {
  const r = Bun.spawnSync(["bun", "run", CLI, "register", "--id", id, "--session", id, "--budget", "1"], { env: envOf(h) });
  if (r.exitCode !== 0) throw new Error("register failed: " + r.stderr.toString().slice(0, 300));
  seed(h, `db.getDb().run(${JSON.stringify(sql)}, [${JSON.stringify(id)}]);`);
}
const spawns = (h: string, id: string, n: number) => seed(h, `db.upsertSession(${JSON.stringify(id)}, '/p', 0, true); db.getDb().run("UPDATE sessions SET agent_spawns = ? WHERE session_id = ?", [${n}, ${JSON.stringify(id)}]);`);
const OVER_CAP = "UPDATE agents SET budget_cap_usd = 1, budget_used_usd = 1.2, tool_calls = 10 WHERE agent_id = ?";
const anyTool = { session_id: S, hook_event_name: "PreToolUse", tool_name: "Read", tool_input: { file_path: "/home/u/a.ts" } };
const goodSpawn = { session_id: S, hook_event_name: "PreToolUse", tool_name: "Agent", tool_input: { subagent_type: "Explore", description: "Find usages of the config loader", prompt: "Search the repository for every place the config loader is called and list the files." } };
const emptySpawn = { session_id: S, hook_event_name: "PreToolUse", tool_name: "Agent", tool_input: { description: "", prompt: "" } };

// ─── §B1 who is calling ───────────────────────────────────────────────────────

describe("§B1 the session comes from the payload (KAV-100)", () => {
  it("BS-101: payload first, then the environment, then the transcript's name", () => {
    expect(whoIsCalling({ session_id: "p" }, { CLAUDE_SESSION_ID: "e" })).toEqual({ sessionId: "p", agentId: "p" });
    expect(whoIsCalling({}, { CLAUDE_SESSION_ID: "e" }).sessionId).toBe("e");
    expect(whoIsCalling({}, { CLAUDE_CODE_SESSION_ID: "c" }).sessionId).toBe("c");
    expect(whoIsCalling({ transcript_path: "/x/y/abc-123.jsonl" }, {}).sessionId).toBe("abc-123");
    expect(whoIsCalling(null, {})).toEqual({ sessionId: "unknown", agentId: "unknown" });
  });

  it("BS-102: a subagent's own id is the caller; without one it is the session", () => {
    expect(whoIsCalling({ session_id: "p", agent_id: "sub-1" }, {})).toEqual({ sessionId: "p", agentId: "sub-1" });
    expect(whoIsCalling({ session_id: "p" }, { CLAUDE_AGENT_ID: "env-agent" }).agentId).toBe("env-agent");
  });

  it("BS-103: an id that is not usable text is not used — nor one that is a path", () => {
    for (const bad of [12345, { id: "x" }, ["x"], "", "x".repeat(300), "../../planted", "a/b", "a\\b", "a\nb"]) {
      expect(whoIsCalling({ session_id: bad, agent_id: bad }, {})).toEqual({ sessionId: "unknown", agentId: "unknown" });
    }
  });
});

// ─── §B2 budget ───────────────────────────────────────────────────────────────

describe("§B2 check-budget", () => {
  it("BS-201: enforce — the payload's session is over its own cap → stopped", () => {
    const h = home(ENFORCE);
    agent(h, S, OVER_CAP);
    const r = hook(h, "check-budget", anyTool);
    expect(r.exit).toBe(2);
    expect(r.stderr).toContain("SOFT STOP");
    expect(hook(h, "check-budget", { ...anyTool, session_id: "someone-else" }).exit).toBe(0);
  });

  it("BS-202: default mode — a spent week is warned about (it was silent)", () => {
    const h = home();
    seed(h, `db.addToBudget(1, { daily: 100, weekly: 400, monthly: 1600 }); db.getDb().run("UPDATE budget_state SET spent_usd = 450 WHERE period LIKE 'weekly:%'");`);
    const r = hook(h, "check-budget", anyTool);
    expect(r.exit).toBe(0);
    expect(r.stderr).toContain("Weekly budget");
  });

  it("BS-203: nothing spent → allowed, in both modes", () => {
    expect(hook(home(), "check-budget", anyTool).exit).toBe(0);
    expect(hook(home(ENFORCE), "check-budget", anyTool).exit).toBe(0);
  });
});

// ─── §B3 spawn ────────────────────────────────────────────────────────────────

describe("§B3 check-spawn on a socket", () => {
  it("BS-301: enforce — a spawn with nothing declared is stopped; a well-described one is not", () => {
    const bad = hook(home(ENFORCE), "check-spawn", emptySpawn);
    expect(bad.exit).toBe(2);
    expect(bad.stderr).toContain("HanumanG");
    const good = hook(home(ENFORCE), "check-spawn", goodSpawn);
    expect(good.exit).toBe(0);
    expect(good.stderr).not.toContain("HanumanG] WARN");
  });

  it("BS-302: default mode — the same two: a warning, and none", () => {
    const bad = hook(home(), "check-spawn", emptySpawn);
    expect(bad.exit).toBe(0);
    expect(bad.stderr).toContain("HanumanG] WARN");
    expect(hook(home(), "check-spawn", goodSpawn).stderr).not.toContain("HanumanG] WARN");
  });

  it("BS-303: enforce — the payload's session at its spawn limit is stopped; another session is not", () => {
    const h = home(ENFORCE);
    spawns(h, S, 60);
    expect(hook(h, "check-spawn", goodSpawn).exit).toBe(2);
    expect(hook(h, "check-spawn", { ...goodSpawn, session_id: "sess-other" }).exit).toBe(0);
    expect(hook(h, "check-spawn", goodSpawn, { CLAUDE_SESSION_ID: "sess-other" }).exit).toBe(2); // the payload wins
  });

  it("BS-304: an agent told to stop cannot spawn, in either mode", () => {
    for (const cfg of [{}, ENFORCE]) {
      const h = home(cfg);
      agent(h, S, "UPDATE agents SET stop_requested = 1 WHERE agent_id = ?");
      expect(hook(h, "check-spawn", goodSpawn).exit).toBe(2);
    }
  });

  it("BS-305: enforce — a session the hook cannot identify is not authorised to spawn", () => {
    const p: Record<string, unknown> = { ...goodSpawn };
    delete p.session_id;
    const r = hook(home(ENFORCE), "check-spawn", p);
    expect(r.exit).toBe(2);
    expect(r.stderr).toContain("authorization");
  });
});

// ─── §B4 held ─────────────────────────────────────────────────────────────────

describe("§B4 the Level 0 valve check runs only when switched on", () => {
  const closeValve = (h: string, id: string) => {
    const r = Bun.spawnSync(["bun", "-e", `const gv = await import(${JSON.stringify(join(ROOT, "src/kavach/gate-valve.ts"))}); gv.closeValve(${JSON.stringify(id)}, 'test');`], { env: envOf(h) });
    if (r.exitCode !== 0) throw new Error("valve seed failed: " + r.stderr.toString().slice(0, 300));
  };

  it("BS-401: default settings — a session whose valve is closed can still spawn", () => {
    const h = home(ENFORCE);
    closeValve(h, S);
    expect(hook(h, "check-spawn", goodSpawn).exit).toBe(0);
  });

  it('BS-402: perm_mask_levels "live" — it cannot; a session with no closed valve still can', () => {
    const h = home({ ...ENFORCE, kavach: { perm_mask_levels: "live" } });
    closeValve(h, S);
    const r = hook(h, "check-spawn", goodSpawn);
    expect(r.exit).toBe(2);
    expect(r.stderr).toContain("KAVACH:L0");
    expect(hook(h, "check-spawn", { ...goodSpawn, session_id: "sess-other" }).exit).toBe(0);
  });
});

// ─── §B5 said so ──────────────────────────────────────────────────────────────

describe("§B5 a call not checked, or checked on the defaults, says so", () => {
  it("BS-501: an unreadable database — allowed, and both hooks say the call was not checked", () => {
    for (const name of ["check-budget", "check-spawn"] as const) {
      const h = home(ENFORCE);
      writeFileSync(join(h, ".aegis/aegis.db"), "this is not a database");
      const r = hook(h, name, name === "check-budget" ? anyTool : goodSpawn);
      expect(r.exit).toBe(0);
      expect(r.stderr).toContain("NOT checked");
    }
  });

  it("BS-502: a config file that cannot be read — both hooks say they run on the defaults", () => {
    for (const body of ['{"enforcement": {"mode": "enforce"', "[]", "null"]) {
      const h = home();
      writeFileSync(join(h, ".aegis/config.json"), body);
      expect(hook(h, "check-budget", anyTool).stderr).toContain("DEFAULT settings");
      expect(hook(h, "check-spawn", goodSpawn).stderr).toContain("DEFAULT settings");
    }
    expect(hook(home(ENFORCE), "check-budget", anyTool).stderr).not.toContain("DEFAULT settings");
  });

  it("BS-503: check-budget with no input at all answers", () => {
    const h = home();
    const r = Bun.spawnSync(["bun", "run", CLI, "check-budget"], { stdin: "ignore", env: envOf(h), timeout: 20_000 });
    expect(r.exitCode).toBe(0);
  });
});

// ─── §B6 limits ───────────────────────────────────────────────────────────────

describe("§B6 stated limits", () => {
  it("LIMIT: the hook does not count spawns — the monitor does", () => {
    const h = home(ENFORCE);
    for (let i = 0; i < 2; i++) hook(h, "check-spawn", goodSpawn);
    const r = Bun.spawnSync(["bun", "-e", `const db = await import(${JSON.stringify(join(ROOT, "src/core/db.ts"))}); console.log(db.getSessionSpawnCount(${JSON.stringify(S)}));`], { env: envOf(h) });
    expect(r.stdout.toString().trim()).toBe("0");
  });

  it("LIMIT: a day's limit of 0 means no limit", () => {
    const h = home({ ...ENFORCE, budget: { daily_limit_usd: 0 } });
    seed(h, "db.addToBudget(50, { daily: 100, weekly: 400, monthly: 1600 });");
    expect(hook(h, "check-budget", anyTool).exit).toBe(0);
  });

  it('LIMIT: a mode spelled any other way than "enforce" is alert', () => {
    const h = home({ enforcement: { mode: "ENFORCE" } });
    seed(h, "db.addToBudget(150, { daily: 100, weekly: 400, monthly: 1600 });");
    expect(hook(h, "check-budget", anyTool).exit).toBe(0);
  });
});
