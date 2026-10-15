// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// Gap 3, the public part: publishing the receipt chain's head. Against a STAND-IN log on this box: nothing
// here is sent to Sigstore. Throwaway HOME; the real CLI runs as a subprocess.

import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, unlinkSync, writeFileSync, chmodSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { spawn, spawnSync, type ChildProcess } from "child_process";

const root = mkdtempSync(join(tmpdir(), "aegis-public-anchor-"));
const cli = join(import.meta.dir, "..", "src/cli/index.ts");
// The stand-in log runs in its OWN process: the CLI is run synchronously below, which would block a server
// living in this process (the first draft of this test deadlocked that way). A path ending in /tamper makes
// it answer with an entry holding another key; GET /count says how many entries it has taken.
const standIn = `
const http = require("http"); let n = 0;
http.createServer((req, res) => {
  if (req.method === "GET") { res.end(String(n)); return; }
  let raw = ""; req.on("data", (c) => (raw += c)); req.on("end", () => {
    n++; const body = JSON.parse(raw);
    if (req.url.endsWith("/tamper")) body.spec.signature.publicKey.content = Buffer.from("-----BEGIN PUBLIC KEY-----\\nnot ours\\n-----END PUBLIC KEY-----\\n").toString("base64");
    res.writeHead(201, { "content-type": "application/json" });
    res.end(JSON.stringify({ ["uuid" + n]: { body: Buffer.from(JSON.stringify(body)).toString("base64"), logIndex: 1000 + n, integratedTime: 1760000000 } }));
  });
}).listen(0, "127.0.0.1", function () { console.log(this.address().port); });`;
let log: ChildProcess;
let url = "";
let tamperUrl = "";
const received = (): number => Number(spawnSync("curl", ["-s", url.replace("/api/v1/log/entries", "/count")], { encoding: "utf8" }).stdout);

beforeAll(async () => {
  log = spawn("node", ["-e", standIn]);
  const port = await new Promise<string>((ok) => log.stdout!.once("data", (d) => ok(String(d).trim())));
  url = `http://127.0.0.1:${port}/api/v1/log/entries`;
  tamperUrl = `${url}/tamper`;
});
afterAll(() => { log.kill(); rmSync(root, { recursive: true, force: true }); });

function box() {
  const home = mkdtempSync(join(root, "b-"));
  mkdirSync(join(home, ".aegis"), { recursive: true });
  writeFileSync(join(home, ".aegis", "config.json"), JSON.stringify({ enforcement: { mode: "monitor" }, kavach: { enabled: true } }));
  const transcript = join(home, "s.jsonl");
  writeFileSync(transcript, JSON.stringify({ type: "assistant", message: { role: "assistant", content: [{ type: "text", text: "Nothing to report." }] } }) + "\n");
  const env: Record<string, string> = { ...(process.env as Record<string, string>), HOME: home, AEGIS_DIR: join(home, ".aegis"), KAVACHOS_MUDRIKA_SECRET: "t" };
  delete env.AEGIS_FLOW_ANCHOR_KEY;
  const run = (...a: string[]) => spawnSync("bun", ["run", cli, ...a], { env, encoding: "utf8", timeout: 30000 });
  const close = (s: string) => spawnSync("bun", ["run", cli, "flow-close"], { env, encoding: "utf8", timeout: 30000, input: JSON.stringify({ hook_event_name: "Stop", session_id: s, transcript_path: transcript, last_assistant_message: "Nothing to report." }) });
  const key = join(home, "anchor.key");
  return { home, env, run, close, key, dir: join(home, ".aegis", "flow-receipts") };
}

describe("aegis flow-receipts keygen / anchor", () => {
  test("keygen writes the key owner-only, prints only the public half, and refuses to overwrite", () => {
    const b = box();
    const r = b.run("flow-receipts", "keygen", "--out", b.key);
    expect(r.status).toBe(0);
    expect(statSync(b.key).mode & 0o777).toBe(0o600);
    expect(r.stdout).toContain("BEGIN PUBLIC KEY");
    expect(r.stdout).not.toContain("PRIVATE");
    expect(b.run("flow-receipts", "keygen", "--out", b.key).status).toBe(2);
  });

  test("a dry run sends nothing", () => {
    const b = box();
    b.run("flow-receipts", "keygen", "--out", b.key);
    b.close("A");
    const before = received();
    const r = b.run("flow-receipts", "anchor", "--key", b.key, "--url", url, "--dry-run");
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("Nothing was sent");
    expect(received()).toBe(before);
  });

  test("anchor publishes the head once, checks the reply, records it; the same head is not sent twice", () => {
    const b = box();
    b.run("flow-receipts", "keygen", "--out", b.key);
    b.close("A"); b.close("B");
    const before = received();
    const r = b.run("flow-receipts", "anchor", "--key", b.key, "--url", url);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("anchored head seq 2");
    expect(received()).toBe(before + 1);
    const rec = JSON.parse(readFileSync(join(b.dir, "anchors.jsonl"), "utf8").trim());
    expect(rec.seq).toBe(2);
    expect(b.run("flow-receipts", "anchor", "--key", b.key, "--url", url).stdout).toContain("already anchored");
    expect(received()).toBe(before + 1);
    expect(b.run("flow-receipts", "verify").stdout).toContain("1 head(s) published");
  });

  test("a chain cut below a published head no longer verifies, naming the anchored head", () => {
    const b = box();
    b.run("flow-receipts", "keygen", "--out", b.key);
    b.close("A"); b.close("B");
    b.run("flow-receipts", "anchor", "--key", b.key, "--url", url);
    const lines = readFileSync(join(b.dir, "chain.jsonl"), "utf8").trim().split("\n");
    unlinkSync(join(b.dir, JSON.parse(lines[1]).file));
    writeFileSync(join(b.dir, "chain.jsonl"), lines[0] + "\n");
    const v = b.run("flow-receipts", "verify");
    expect(v.status).toBe(1);
    expect(v.stdout).toContain("anchored head seq 2");
  });

  test("refused here: a key others can read, a broken chain, no key", () => {
    const b = box();
    b.run("flow-receipts", "keygen", "--out", b.key);
    b.close("A");
    const before = received();
    chmodSync(b.key, 0o644);
    expect(b.run("flow-receipts", "anchor", "--key", b.key, "--url", url).status).toBe(2);
    chmodSync(b.key, 0o600);
    expect(b.run("flow-receipts", "anchor", "--url", url).status).toBe(2);
    const idx = join(b.dir, "chain.jsonl");
    writeFileSync(idx, readFileSync(idx, "utf8").replace(/"hash":"[0-9a-f]{4}/, '"hash":"0000'));
    expect(b.run("flow-receipts", "anchor", "--key", b.key, "--url", url).status).toBe(2);
    expect(received()).toBe(before);
  });

  test("a reply that does not hold our key is not recorded as an anchor", () => {
    const b = box();
    b.run("flow-receipts", "keygen", "--out", b.key);
    b.close("A");
    const r = b.run("flow-receipts", "anchor", "--key", b.key, "--url", tamperUrl);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("not our key");
    let recorded = true;
    try { readFileSync(join(b.dir, "anchors.jsonl"), "utf8"); } catch { recorded = false; }
    expect(recorded).toBe(false);
  });
});
