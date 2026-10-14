// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// Layer C (GTP-024, 2026-10-15): the cockpit's event pages are public with no login, so an event that
// carries a flow id (real agent work) is never served there, even if it was written to the public store.
// Uses a scratch AEGIS_DIR; the store path is read when the cockpit first opens it.

import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

const dir = mkdtempSync(join(tmpdir(), "acc-public-"));
process.env.AEGIS_DIR = dir;

const { default: Fastify } = await import("fastify");
const { registerAccRoutes } = await import("../src/dashboard/routes/acc");
const { SqliteEventWriter, defaultAccEventsDbPath } = await import("../src/acc/bus");

const app = Fastify();
registerAccRoutes(app);
let base = "";

beforeAll(async () => {
  if (!defaultAccEventsDbPath().startsWith(dir)) throw new Error(`refusing: store at ${defaultAccEventsDbPath()}`);
  const w = new SqliteEventWriter();
  const at = new Date().toISOString();
  w.write({ receipt_id: "demo1", primitive: "chitta-detect", event_type: "scan.evaluated", emitted_at: at, agent_id: "demo-agent" });
  w.write({ receipt_id: "real1", primitive: "chitta-detect", event_type: "scan.evaluated", emitted_at: at, agent_id: "demo-agent", flow_id: "cc:S", turn_id: "tool:T" });
  w.close();
  await app.listen({ port: 0, host: "127.0.0.1" });
  base = `http://127.0.0.1:${(app.server.address() as { port: number }).port}`;
});
afterAll(async () => {
  await app.close();
  rmSync(dir, { recursive: true, force: true });
});

const ids = async (q: string) => ((await (await fetch(`${base}/api/acc/events${q}`)).json()) as { events: Array<{ receipt_id: string }> }).events.map((e) => e.receipt_id);

describe("public cockpit never serves flow events", () => {
  test("latest events", async () => { expect(await ids("")).toEqual(["demo1"]); });
  test("by primitive", async () => { expect(await ids("?primitive=chitta-detect")).toEqual(["demo1"]); });
  test("by agent", async () => { expect(await ids("?agent_id=demo-agent")).toEqual(["demo1"]); });
});
