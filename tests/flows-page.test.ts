// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// P1c (GTP-018/024): the login-only flow page. Uses a scratch AEGIS_DIR only.

import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

const dir = mkdtempSync(join(tmpdir(), "flows-page-"));
process.env.AEGIS_DIR = dir;

const { default: Fastify } = await import("fastify");
const { registerFlowRoutes } = await import("../src/dashboard/routes/flows");
const { buildFlowTree, summariseFlows, readFlowEvents, recordToolDecision, defaultFlowEventsDbPath } = await import("../src/acc/flow-events");
const { isPublicRoute } = await import("../src/dashboard/public-routes");

const HOSTILE = `<img src=x onerror=alert(1)>`;
const app = Fastify();
registerFlowRoutes(app);
let base = "";

beforeAll(async () => {
  if (!defaultFlowEventsDbPath().startsWith(dir)) throw new Error(`refusing: store at ${defaultFlowEventsDbPath()}`);
  const h = (x: Record<string, unknown>) => ({ hook_event_name: "PreToolUse", session_id: "S1", prompt_id: "P1", tool_name: "Read", ...x });
  recordToolDecision(h({ tool_use_id: "T1" }), { exitCode: 0 });
  recordToolDecision(h({ tool_use_id: "T2", tool_name: "Bash" }), { exitCode: 2, ruleId: "KAV-096", verdict: "QUARANTINED" });
  recordToolDecision(h({ tool_use_id: "T3", agent_id: "A1", agent_type: "Explore", tool_name: HOSTILE }), { exitCode: 0 });
  recordToolDecision(h({ session_id: "S2", tool_use_id: "T4" }), { exitCode: 0 });
  await app.listen({ port: 0, host: "127.0.0.1" });
  base = `http://127.0.0.1:${(app.server.address() as { port: number }).port}`;
});
afterAll(async () => {
  await app.close();
  rmSync(dir, { recursive: true, force: true });
});

describe("flow summary and tree", () => {
  test("one line per flow, with tool calls, blocks and subagents", () => {
    const s = summariseFlows(readFlowEvents());
    const s1 = s.find((f) => f.flow_id === "cc:S1")!;
    expect(s).toHaveLength(2);
    expect(s1).toMatchObject({ turns: 3, blocked: 1, subagents: 1 });
  });

  test("the tree has the prompt branch and the subagent branch, with their calls in order", () => {
    const tree = buildFlowTree(readFlowEvents({ flowId: "cc:S1" }));
    expect(tree.map((b) => [b.parent, b.kind, b.turns.map((t) => t.turn_id)])).toEqual([
      ["prompt:P1", "prompt", ["tool:T1", "tool:T2"]],
      ["agent:A1", "subagent", ["tool:T3"]],
    ]);
    expect(tree[1].agent_type).toBe("Explore");
  });

  test("a store that does not exist reads as no flows, and is not created", () => {
    expect(readFlowEvents({ path: join(dir, "absent.db") })).toEqual([]);
    expect(readFlowEvents({ path: join(dir, "absent.db"), flowId: "x" })).toEqual([]);
  });
});

describe("the pages", () => {
  test("none of the flow routes is public", () => {
    for (const r of ["/flows", "/flows/:id", "/api/flows", "/api/flows/:id"]) expect(isPublicRoute("GET", r, r)).toBe(false);
  });

  test("the list links each flow", async () => {
    const html = await (await fetch(`${base}/flows`)).text();
    expect(html).toContain(`href="/flows/cc%3AS1"`);
    expect(html).toContain(`href="/flows/cc%3AS2"`);
  });

  test("the flow page shows the branches and escapes what came from hook input", async () => {
    const html = await (await fetch(`${base}/flows/${encodeURIComponent("cc:S1")}`)).text();
    expect(html).toContain("QUARANTINED");
    expect(html).toContain("KAV-096");
    expect(html).toContain("Subagent");
    expect(html).not.toContain(HOSTILE);
    expect(html).toContain("&lt;img src=x onerror=alert(1)&gt;");
    // P3: a flow with no mandate says so, never shows a made-up root
    expect(html).toContain("no root of authority recorded for this flow");
  });

  test("JSON: the list and one flow", async () => {
    const list = (await (await fetch(`${base}/api/flows`)).json()) as { flows: Array<{ flow_id: string }> };
    expect(list.flows.map((f) => f.flow_id).sort()).toEqual(["cc:S1", "cc:S2"]);
    const one = (await (await fetch(`${base}/api/flows/${encodeURIComponent("cc:S1")}`)).json()) as { events: unknown[] };
    expect(one.events).toHaveLength(3);
  });
});
