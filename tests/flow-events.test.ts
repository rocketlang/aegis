// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// Flow events (GTP-018/024, P1): one private record per tool-call decision. Uses only a temporary file.

import { afterAll, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, statSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { recordToolDecision, toolDecisionEvent } from "../src/acc/flow-events";
import { SqliteEventWriter } from "../src/acc/bus";

const dir = mkdtempSync(join(tmpdir(), "flow-events-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const SECRET = "sk-live-THIS-MUST-NEVER-APPEAR";
const hook = (extra: Record<string, unknown> = {}) => ({
  hook_event_name: "PreToolUse", session_id: "S", prompt_id: "P", tool_use_id: "T", tool_name: "Bash",
  tool_input: { command: `curl -H 'Authorization: ${SECRET}' https://example.invalid/x` }, cwd: "/root/private-dir",
  ...extra,
});

describe("toolDecisionEvent", () => {
  test("allowed main-agent call: flow, turn, parent from the hook input", () => {
    const e = toolDecisionEvent(hook(), { exitCode: 0 })!;
    expect(e).toMatchObject({ primitive: "aegis", event_type: "tool.decided", verdict: "ALLOWED", summary: "Bash",
      flow_id: "cc:S", turn_id: "tool:T", parent_turn_id: "prompt:P" });
    expect(e.rules_fired).toBeUndefined();
  });

  test("blocked subagent call: the subagent is the parent, the rule is recorded", () => {
    const e = toolDecisionEvent(hook({ agent_id: "A", agent_type: "Explore" }), { exitCode: 2, ruleId: "KAV-096", verdict: "QUARANTINED", category: "persistence" })!;
    expect(e).toMatchObject({ verdict: "QUARANTINED", rules_fired: ["KAV-096"], agent_id: "A", parent_turn_id: "agent:A",
      payload: { hook: "PreToolUse", category: "persistence", agent_type: "Explore" } });
  });

  test("a block without a recorded rule is still a block", () => {
    expect(toolDecisionEvent(hook(), { exitCode: 2 })!.verdict).toBe("BLOCKED");
  });

  test("never carries the tool's input, the working directory or a secret in it", () => {
    const text = JSON.stringify(toolDecisionEvent(hook(), { exitCode: 2, ruleId: "R", category: "c" }));
    expect(text).not.toContain(SECRET);
    expect(text).not.toContain("curl");
    expect(text).not.toContain("private-dir");
  });

  test("nothing to record: no session, or not a PreToolUse call", () => {
    expect(toolDecisionEvent(hook({ session_id: undefined }), { exitCode: 0 })).toBeNull();
    expect(toolDecisionEvent(hook({ hook_event_name: "PostToolUse" }), { exitCode: 0 })).toBeNull();
  });
});

describe("recordToolDecision", () => {
  test("writes to the given private store, owner-only, readable by flow", () => {
    const path = join(dir, "flow-events.db");
    recordToolDecision(hook(), { exitCode: 0 }, path);
    recordToolDecision(hook({ tool_use_id: "T2", agent_id: "A" }), { exitCode: 2, ruleId: "KAV-001" }, path);
    expect(statSync(path).mode & 0o777).toBe(0o600);
    const w = new SqliteEventWriter({ path });
    const flow = w.queryByFlow("cc:S");
    w.close();
    expect(flow.map((e) => [e.turn_id, e.verdict])).toEqual([["tool:T", "ALLOWED"], ["tool:T2", "BLOCKED"]]);
  });

  test("AEGIS_FLOW_EVENTS=off writes nothing", () => {
    const path = join(dir, "off.db");
    process.env.AEGIS_FLOW_EVENTS = "off";
    try { recordToolDecision(hook(), { exitCode: 0 }, path); } finally { delete process.env.AEGIS_FLOW_EVENTS; }
    expect(() => statSync(path)).toThrow();
  });

  test("never throws, even when the store cannot be opened", () => {
    expect(() => recordToolDecision(hook(), { exitCode: 0 }, "/proc/forbidden/flow-events.db")).not.toThrow();
  });
});

describe("P2: which tool call spawned a subagent (read, never inferred)", () => {
  const { spawnLink, subagentMetaPath } = require("../src/acc/flow-events") as typeof import("../src/acc/flow-events");
  const TP = "/root/.claude/projects/-root/S.jsonl";
  const files: Record<string, string> = {
    "/root/.claude/projects/-root/S/subagents/agent-A1.meta.json": JSON.stringify({ agentType: "Explore", toolUseId: "toolu_SPAWN1", spawnDepth: 1 }),
    "/root/.claude/projects/-root/S/subagents/agent-BAD.meta.json": JSON.stringify({ toolUseId: "../../etc/passwd" }),
  };
  const read = (p: string) => files[p] ?? null;

  test("the meta file beside the transcript names the spawning call and depth", () => {
    expect(spawnLink({ transcript_path: TP, agent_id: "A1" }, read)).toEqual({ spawned_by: "tool:toolu_SPAWN1", spawn_depth: 1 });
  });
  test("no file, a bad id in it, or an id that tries to leave the folder: no link", () => {
    expect(spawnLink({ transcript_path: TP, agent_id: "NOPE" }, read)).toBeNull();
    expect(spawnLink({ transcript_path: TP, agent_id: "BAD" }, read)).toBeNull();
    expect(subagentMetaPath(TP, "../../x")).toBeNull();
    expect(subagentMetaPath("relative/S.jsonl", "A1")).toBeNull();
    expect(subagentMetaPath("/x/S.txt", "A1")).toBeNull();
  });
  test("a subagent's event carries the link; a main-agent event never looks", () => {
    let looked = 0;
    const counting = (p: string) => { looked++; return read(p); };
    const sub = toolDecisionEvent(hook({ transcript_path: TP, agent_id: "A1" }), { exitCode: 0 }, new Date(), counting)!;
    expect(sub.payload).toMatchObject({ spawned_by: "tool:toolu_SPAWN1", spawn_depth: 1 });
    const main = toolDecisionEvent(hook({ transcript_path: TP }), { exitCode: 0 }, new Date(), counting)!;
    expect((main.payload as Record<string, unknown>).spawned_by).toBeUndefined();
    expect(looked).toBe(1);
  });
});

describe("P2: the tree nests a subagent under the call that spawned it", () => {
  const { buildFlowTree } = require("../src/acc/flow-events") as typeof import("../src/acc/flow-events");
  const at = (n: number) => new Date(Date.UTC(2026, 9, 15, 0, 0, n)).toISOString();
  const e = (n: number, turn: string, parent: string, payload: Record<string, unknown> = {}) =>
    ({ receipt_id: `r${n}`, primitive: "aegis", event_type: "tool.decided", emitted_at: at(n), flow_id: "cc:S", turn_id: turn, parent_turn_id: parent, payload });
  test("prompt → its Agent call → subagent → that subagent's own subagent", () => {
    const tree = buildFlowTree([
      e(1, "tool:T1", "prompt:P1"),
      e(2, "tool:SPAWN_A", "prompt:P1"),
      e(3, "tool:T3", "agent:A", { spawned_by: "tool:SPAWN_A", spawn_depth: 1, agent_type: "Explore" }),
      e(4, "tool:SPAWN_B", "agent:A", { spawned_by: "tool:SPAWN_A", spawn_depth: 1 }),
      e(5, "tool:T5", "agent:B", { spawned_by: "tool:SPAWN_B", spawn_depth: 2 }),
      e(6, "tool:T6", "prompt:P2"),
      e(7, "tool:T7", "agent:C"),
    ]);
    expect(tree.map((b) => [b.parent, b.spawned_in ?? null, b.spawn_depth ?? null])).toEqual([
      ["prompt:P1", null, null],
      ["agent:A", "prompt:P1", 1],
      ["agent:B", "agent:A", 2],
      ["prompt:P2", null, null],
      ["agent:C", null, null],
    ]);
  });
});
