// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// Gap 3 of the flow guardrails, the part on this box: flow receipts form a signed chain that shows any
// change, removal or reordering. The real Stop hook runs as a subprocess under a throwaway HOME.

import { afterAll, describe, expect, test } from "bun:test";
import { appendFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { spawn, spawnSync } from "child_process";

const root = mkdtempSync(join(tmpdir(), "aegis-receipt-chain-"));
afterAll(() => rmSync(root, { recursive: true, force: true }));
const cli = join(import.meta.dir, "..", "src/cli/index.ts");

function box() {
  const home = mkdtempSync(join(root, "b-"));
  mkdirSync(join(home, ".aegis"), { recursive: true });
  writeFileSync(join(home, ".aegis", "config.json"), JSON.stringify({ enforcement: { mode: "monitor" }, kavach: { enabled: true } }));
  const approvers = join(home, "approvers.json");
  writeFileSync(approvers, JSON.stringify({ owners: { telegram: ["555000111"] } }));
  const transcript = join(home, "s.jsonl");
  writeFileSync(transcript, JSON.stringify({ type: "assistant", message: { role: "assistant", content: [{ type: "text", text: "Nothing to report." }] } }) + "\n");
  const env: Record<string, string> = { ...(process.env as Record<string, string>), HOME: home, AEGIS_DIR: join(home, ".aegis"), AOS_APPROVERS_FILE: approvers, KAVACHOS_MUDRIKA_SECRET: "t" };
  return { home, env, transcript, dir: join(home, ".aegis", "flow-receipts") };
}
const stopInput = (session: string, transcript: string) => JSON.stringify({ hook_event_name: "Stop", session_id: session, transcript_path: transcript, last_assistant_message: "Nothing to report.", stop_hook_active: false });
const close = (env: Record<string, string>, session: string, transcript: string) =>
  spawnSync("bun", ["run", cli, "flow-close"], { input: stopInput(session, transcript), env, encoding: "utf8", timeout: 30000 });
const verify = (env: Record<string, string>) => spawnSync("bun", ["run", cli, "flow-receipts", "verify"], { env, encoding: "utf8", timeout: 30000 });
const index = (dir: string) => readFileSync(join(dir, "chain.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l));

describe("the flow-receipt chain", () => {
  test("three receipts form a chain that verifies; each names the one before", () => {
    const b = box();
    for (const s of ["A", "B", "C"]) expect(close(b.env, s, b.transcript).status).toBe(0);
    const lines = index(b.dir);
    expect(lines.map((l) => l.seq)).toEqual([1, 2, 3]);
    expect(lines[0].prev).toBe("0".repeat(64));
    expect(lines[1].prev).toBe(lines[0].hash);
    const r2 = JSON.parse(readFileSync(join(b.dir, lines[1].file), "utf8"));
    expect(r2.chain).toEqual({ seq: 2, prev: lines[0].hash });
    const v = verify(b.env);
    expect(v.status).toBe(0);
    expect(v.stdout).toContain("chain holds: 3 receipt(s)");
    const head = JSON.parse(spawnSync("bun", ["run", cli, "flow-receipts", "head"], { env: b.env, encoding: "utf8" }).stdout);
    expect(head).toEqual({ seq: 3, hash: lines[2].hash });
  });

  test("a receipt changed after it was written breaks the chain, and verify names it", () => {
    const b = box();
    for (const s of ["A", "B", "C"]) close(b.env, s, b.transcript);
    const f = join(b.dir, index(b.dir)[1].file);
    const before = readFileSync(f, "utf8");
    const r = JSON.parse(before);
    r.status = r.status === "open" ? "closed" : "open";
    writeFileSync(f, JSON.stringify(r, null, 2));
    expect(readFileSync(f, "utf8")).not.toBe(before); // the change really happened
    const v = verify(b.env);
    expect(v.status).toBe(1);
    expect(v.stdout).toContain("seq 2");
    expect(v.stdout).toContain("changed after it was written");
  });

  test("a receipt removed from the middle (file and index line) breaks every link after it", () => {
    const b = box();
    for (const s of ["A", "B", "C"]) close(b.env, s, b.transcript);
    const lines = index(b.dir);
    unlinkSync(join(b.dir, lines[1].file));
    writeFileSync(join(b.dir, "chain.jsonl"), [lines[0], lines[2]].map((l) => JSON.stringify(l)).join("\n") + "\n");
    const v = verify(b.env);
    expect(v.status).toBe(1);
    expect(v.stdout).toMatch(/out of order|previous/);
  });

  test("an index line forged for a receipt that was never chained is caught by its signature or link", () => {
    const b = box();
    close(b.env, "A", b.transcript);
    const lines = index(b.dir);
    const fake = join(b.dir, "forged.json");
    writeFileSync(fake, JSON.stringify({ receipt_version: "v1", flow_id: "cc:X", status: "closed", chain: { seq: 2, prev: lines[0].hash }, signature: "x" }, null, 2));
    const hash = require("crypto").createHash("sha256").update(readFileSync(fake)).digest("hex");
    appendFileSync(join(b.dir, "chain.jsonl"), JSON.stringify({ seq: 2, file: "forged.json", hash, prev: lines[0].hash, at: "now" }) + "\n");
    const v = verify(b.env);
    expect(v.status).toBe(1);
    expect(v.stdout).toContain("signature does not verify");
  });

  test("six sessions closing at the same moment leave one straight chain, no fork", async () => {
    const b = box();
    await Promise.all(["P", "Q", "R", "S", "T", "U"].map((s) => new Promise<void>((done) => {
      const c = spawn("bun", ["run", cli, "flow-close"], { env: b.env });
      c.stdin.end(stopInput(s, b.transcript));
      c.on("close", () => done());
    })));
    const lines = index(b.dir);
    expect(lines.map((l) => l.seq)).toEqual([1, 2, 3, 4, 5, 6]);
    expect(verify(b.env).status).toBe(0);
  });
});
