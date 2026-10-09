// SPDX-License-Identifier: AGPL-3.0-only
// The signed refusal ledger, ANCHORED in a public log: the real authority signs, the real command
// submits, the real verifier reads the log back, and the failures are forced.
//
//   an empty ledger                         → nothing is sent
//   two rows                                → one leaf, signed by the LEDGER key, proven included, receipt kept
//   the same tail again                     → nothing new is sent; with the receipt lost, the log still holds one leaf
//   a third row                             → a second leaf
//   ledger-verify --anchor-log              → clean, names the latest anchored row and the rows not yet anchored
//   the file cut back below an anchor       → TRUNCATION OR REWRITE, exit 1
//   the file cut back to the last anchor    → clean (the stated limit: rows after the last anchor are not covered)
//   a leaf naming our key that we never signed → ignored
//   a wrong log key                         → UNVERIFIABLE, exit 2
//   a log that swaps a leaf it shows        → UNVERIFIABLE (the root does not rebuild); a partial read does not see it
//   a ledger with no anchor                 → UNVERIFIABLE, exit 2
//   a log that wants a token                → refused without one, exit 1, no receipt; anchored with one (text and JSON file)
//
// The log here is a stand-in written for this test from the protocol (log.md): its tree and proofs are
// computed by code in THIS file, not by the code under test. What this does NOT prove: anything about a
// real log (see the dated rehearsal against the public test log), the cosigning witnesses, or the uid
// boundary. Everything runs as one user.
import { describe, it, expect, beforeAll, afterAll } from "bun:test";
import { createHash, generateKeyPairSync, sign, verify, randomBytes, createPublicKey } from "crypto";
import { existsSync, mkdtempSync, readFileSync, writeFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { startApproverDaemon } from "../src/kavach/approver-daemon.ts";
import { askLedgerAuthority } from "../src/kavach/approver-client.ts";
import { signLedgerRow, generateLedgerKeypair, rowHash } from "../src/core/ledger-sign.ts";
import { verifyLeafSignature, verifyAnchor, merkleRoot, verifyInclusion, type Anchor } from "../src/core/ledger-anchor.ts";

const ROOT = new URL("..", import.meta.url).pathname;
const SOURCE = "anchor-test-box";
const sha = (...b: Uint8Array[]) => { const h = createHash("sha256"); b.forEach((x) => h.update(x)); return h.digest(); };
const rawPub = (k: ReturnType<typeof createPublicKey>) => Buffer.from(k.export({ format: "der", type: "spki" })).subarray(-32);

// ── a stand-in log ──────────────────────────────────────────────────────────────────────────────
type Leaf = [checksum: string, signature: string, keyHash: string];
const mth = (d: Buffer[]): Buffer => {
  if (d.length === 0) return sha();
  if (d.length === 1) return d[0];
  let k = 1; while (k * 2 < d.length) k *= 2;
  return sha(Buffer.from([1]), mth(d.slice(0, k)), mth(d.slice(k)));
};
const auditPath = (m: number, d: Buffer[]): Buffer[] => {
  if (d.length <= 1) return [];
  let k = 1; while (k * 2 < d.length) k *= 2;
  return m < k ? [...auditPath(m, d.slice(0, k)), mth(d.slice(k))] : [...auditPath(m - k, d.slice(k)), mth(d.slice(0, k))];
};

function standInLog(opts: { token?: string } = {}) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const key = rawPub(publicKey);
  const leaves: Leaf[] = []; const seenOnce = new Set<string>();
  const state = { swapIndex: -1, addLeafCalls: 0 };
  const lh = (l: Leaf) => sha(Buffer.from([0]), Buffer.from(l[0], "hex"), Buffer.from(l[1], "hex"), Buffer.from(l[2], "hex"));
  const foreign = (): Leaf => [randomBytes(32).toString("hex"), randomBytes(64).toString("hex"), randomBytes(32).toString("hex")];
  for (let i = 0; i < 5; i++) leaves.push(foreign());
  const server = Bun.serve({
    port: 0, hostname: "127.0.0.1",
    async fetch(req) {
      const path = new URL(req.url).pathname; const text = (s: string, status = 200) => new Response(s, { status });
      if (path === "/get-tree-head") {
        const root = mth(leaves.map(lh));
        const signed = `sigsum.org/v1/tree/${sha(key).toString("hex")}\n${leaves.length}\n${root.toString("base64")}\n`;
        return text(`size=${leaves.length}\nroot_hash=${root.toString("hex")}\nsignature=${sign(null, Buffer.from(signed), privateKey).toString("hex")}\ncosignature=${"ab".repeat(32)} 1 ${"cd".repeat(64)}\n`);
      }
      if (path === "/add-leaf" && req.method === "POST") {
        state.addLeafCalls++;
        if (opts.token && req.headers.get("sigsum-token") !== opts.token) return text("(403) validating token signature failed\n", 403);
        const f = Object.fromEntries((await req.text()).split("\n").filter(Boolean).map((l) => l.split("=")));
        const checksum = sha(Buffer.from(f.message, "hex")); const pub = Buffer.from(f.public_key, "hex");
        const okSig = verify(null, Buffer.concat([Buffer.from("sigsum.org/v1/tree-leaf\0"), checksum]),
          createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), pub]), format: "der", type: "spki" }), Buffer.from(f.signature, "hex"));
        if (!okSig) return text("(403) bad leaf signature\n", 403);
        const leaf: Leaf = [checksum.toString("hex"), f.signature, sha(pub).toString("hex")];
        const id = leaf.join(" ");
        if (leaves.some((l) => l.join(" ") === id)) return text("", 200);
        if (!seenOnce.has(id)) { seenOnce.add(id); return text("(202) Accepted\n", 202); }   // a real log commits on a later request
        leaves.push(leaf); leaves.push(foreign());
        return text("", 200);
      }
      let m = path.match(/^\/get-inclusion-proof\/(\d+)\/([0-9a-f]{64})$/);
      if (m) {
        const hashes = leaves.slice(0, Number(m[1])).map(lh); const i = hashes.findIndex((h) => h.toString("hex") === m![2]);
        if (i < 0) return text("(404) not found\n", 404);
        return text(`leaf_index=${i}\n` + auditPath(i, hashes).map((h) => `node_hash=${h.toString("hex")}\n`).join(""));
      }
      m = path.match(/^\/get-leaves\/(\d+)\/(\d+)$/);
      if (m) {
        const from = Number(m[1]), to = Math.min(Number(m[2]), from + 3, leaves.length);   // three at a time: the reader must page
        return text(leaves.slice(from, to).map((l, k) => `leaf=${(from + k === state.swapIndex ? foreign() : l).join(" ")}\n`).join(""));
      }
      return text("(404)\n", 404);
    },
  });
  return { url: `http://127.0.0.1:${server.port}`, key: key.toString("hex"), leaves, state, foreign, stop: () => server.stop(true) };
}

// ── the rig: a real authority on sockets, the real CLI ──────────────────────────────────────────
const dir = mkdtempSync(join(tmpdir(), "aegis-ledger-anchor-"));
const store = join(dir, "store"), home = join(dir, "home"), sock = join(dir, "consume.sock");
const pubFile = join(store, "ledger-signing.pub"), ledgerFile = join(store, "refusals.signed.jsonl"), receipts = join(home, "ledger-anchors.jsonl");
let daemon: ReturnType<typeof startApproverDaemon>;
let log: ReturnType<typeof standInLog>;

// Not spawnSync: the stand-in log and the authority live in THIS process and must keep answering while the command runs.
async function cli(args: string[], env: Record<string, string> = {}) {
  const p = Bun.spawn(["bun", join(ROOT, "src/cli/index.ts"), ...args], { env: { ...process.env, AEGIS_HOME: home, AEGIS_LEDGER_PUBKEY_FILE: pubFile, AEGIS_ANCHOR_WAIT_MS: "50", ...env }, stdout: "pipe", stderr: "pipe" });
  const [out, err, code] = await Promise.all([new Response(p.stdout).text(), new Response(p.stderr).text(), p.exited]);
  return { code, out: out + err };
}
const anchor = (extra: string[] = [], l = log) => cli(["ledger-anchor", "--log", l.url, "--log-key", l.key, "--socket", sock, "--receipts", receipts, ...extra]);
const verifyCli = (file: string, extra: string[] = [], l = log) => cli(["ledger-verify", file, "--source", SOURCE, "--anchor-log", l.url, "--anchor-log-key", l.key, ...extra]);
const ours = (l = log) => { const kh = sha(rawPub(createPublicKey(readFileSync(pubFile, "utf-8")))).toString("hex"); return l.leaves.filter((x) => x[2] === kh); };
const refuse = (rule: string) => daemon.ledger.record({ gate: "test-gate", rule });
const cutTo = (n: number) => { const f = join(dir, `cut-${n}.jsonl`); writeFileSync(f, readFileSync(ledgerFile, "utf-8").split("\n").filter(Boolean).slice(0, n).join("\n") + "\n"); return f; };

beforeAll(async () => {
  daemon = startApproverDaemon({ storeDir: store, consumeSocketPath: sock, approveSocketPath: join(dir, "approve.sock"), ledgerSource: SOURCE, log: () => {} });
  log = standInLog();
  for (let i = 0; i < 50 && !existsSync(sock); i++) await new Promise((r) => setTimeout(r, 50));
});
afterAll(() => { daemon.stop(); log.stop(); rmSync(dir, { recursive: true, force: true }); });

describe("ledger anchor, wired: authority signs, command submits, verifier reads the log", () => {
  it("an empty ledger sends nothing, and the authority will not sign an anchor for it", async () => {
    const r = await anchor();
    expect(r.code).toBe(0); expect(r.out).toContain("nothing to anchor"); expect(log.state.addLeafCalls).toBe(0);
    const a = await askLedgerAuthority<Anchor>(sock, "anchor");
    expect(a.ok).toBe(false); expect(a.error).toContain("empty");
  });

  it("two rows become one leaf signed by the ledger's own key, proven included, with a receipt", async () => {
    refuse("R-1"); refuse("R-2");
    const r = await anchor();
    expect(r.out).toContain("ANCHORED — seq 2"); expect(r.code).toBe(0);
    const mine = ours(); expect(mine.length).toBe(1);
    const pem = readFileSync(pubFile, "utf-8");
    expect(verifyLeafSignature(mine[0][0], mine[0][1], pem)).toBe(true);
    const rec = JSON.parse(readFileSync(receipts, "utf-8").trim().split("\n")[0]);
    expect(rec.max_seq).toBe(2); expect(rec.checksum).toBe(mine[0][0]); expect(rec.log_key).toBe(log.key);
    const a = (await askLedgerAuthority<Anchor>(sock, "anchor")).value as Anchor;
    expect(verifyAnchor(a, pem)).toBe(true);
    expect(verifyAnchor({ ...a, max_seq: 3 }, pem)).toBe(false);   // the fields are rebuilt from the statement, not believed
  });

  it("the same tail is not sent twice; with the receipt lost the log still ends up holding one leaf", async () => {
    const calls = log.state.addLeafCalls;
    const again = await anchor();
    expect(again.code).toBe(0); expect(again.out).toContain("already anchored"); expect(log.state.addLeafCalls).toBe(calls);
    rmSync(receipts);
    const resent = await anchor();
    expect(resent.code).toBe(0); expect(resent.out).toContain("ANCHORED — seq 2"); expect(ours().length).toBe(1);
  });

  it("--dry-run asks and checks and sends nothing", async () => {
    refuse("R-3");
    const calls = log.state.addLeafCalls;
    const r = await anchor(["--dry-run"]);
    expect(r.code).toBe(0); expect(r.out).toContain("dry run"); expect(log.state.addLeafCalls).toBe(calls);
  });

  it("a ledger that has grown gets a second leaf", async () => {
    const r = await anchor();
    expect(r.code).toBe(0); expect(r.out).toContain("ANCHORED — seq 3"); expect(ours().length).toBe(2);
  });

  it("ledger-verify reads the whole log, rebuilds its root, and finds every anchor is a state the file contains", async () => {
    refuse("R-4");   // not anchored
    const r = await verifyCli(ledgerFile);
    expect(r.out).toContain("holds 2 anchor(s)"); expect(r.out).toContain("the latest is seq 3"); expect(r.out).toContain("root rebuilt");
    expect(r.out).toContain("1 row(s) after seq 3 are not anchored yet"); expect(r.out).toContain("not checked");
    expect(r.code).toBe(0);
  });

  it("a file cut back below an anchor is TRUNCATION OR REWRITE, exit 1", async () => {
    const r = await verifyCli(cutTo(2));
    expect(r.out).toContain("TRUNCATION OR REWRITE"); expect(r.out).toContain("1 anchor(s)"); expect(r.code).toBe(1);
  });

  it("a file cut back only to the last anchor reads clean: rows after the last anchor are not covered (the stated limit)", async () => {
    const r = await verifyCli(cutTo(3));
    expect(r.code).toBe(0); expect(r.out).toContain("the latest is seq 3"); expect(r.out).not.toContain("not anchored yet");
  });

  it("a rewritten ledger of the same length is caught: its rows cannot produce the anchored leaves", async () => {
    // someone WITH the key rewrites rows 1..3 with other content; every row verifies, the chain is whole
    const f = join(dir, "rewritten.jsonl"); const key = readFileSync(join(store, "ledger-signing.key"), "utf-8");
    let prev = ""; const rows = [];
    for (let i = 1; i <= 3; i++) { const row = signLedgerRow({ ts: "2026-01-01T00:00:00.000Z", kind: "refused", gate: "other", rule: null, session: null }, i, prev, key); rows.push(row); prev = rowHash(row); }
    writeFileSync(f, rows.map((r) => JSON.stringify(r)).join("\n") + "\n");
    const r = await verifyCli(f);
    expect(r.out).toContain("OK — 3 row(s)"); expect(r.out).toContain("TRUNCATION OR REWRITE"); expect(r.code).toBe(1);
  });

  it("a leaf that names our key hash but was not signed by our key is ignored", async () => {
    const kh = sha(rawPub(createPublicKey(readFileSync(pubFile, "utf-8")))).toString("hex");
    log.leaves.push([randomBytes(32).toString("hex"), randomBytes(64).toString("hex"), kh]);
    const r = await verifyCli(ledgerFile);
    expect(r.code).toBe(0); expect(r.out).toContain("holds 2 anchor(s)");
  });

  it("a wrong log key is UNVERIFIABLE, exit 2", async () => {
    const r = await cli(["ledger-verify", ledgerFile, "--source", SOURCE, "--anchor-log", log.url, "--anchor-log-key", "11".repeat(32)]);
    expect(r.out).toContain("UNVERIFIABLE"); expect(r.out).toContain("not signed by the log key"); expect(r.code).toBe(2);
  });

  it("a log that swaps a leaf it shows is caught by the whole read and missed by a partial one, which says it is partial", async () => {
    log.state.swapIndex = 1;   // a foreign leaf near the start is shown as something else
    const whole = await verifyCli(ledgerFile);
    expect(whole.out).toContain("do not rebuild the root"); expect(whole.code).toBe(2);
    const partial = await verifyCli(ledgerFile, ["--anchor-from", "3"]);
    expect(partial.code).toBe(0); expect(partial.out).toContain("read from index 3"); expect(partial.out).toContain("not ruled out");
    log.state.swapIndex = -1;
  });

  it("a ledger with no anchor in the log is UNVERIFIABLE for truncation, exit 2", async () => {
    const other = standInLog();
    try { const r = await verifyCli(ledgerFile, [], other); expect(r.out).toContain("no anchor"); expect(r.code).toBe(2); } finally { other.stop(); }
  });

  it("a log that wants a token refuses without one (exit 1, no receipt) and anchors with one, from a text or a JSON file", async () => {
    const token = `ankr.example ${"0f".repeat(64)}`;
    const gated = standInLog({ token });
    try {
      const rc = join(dir, "gated-receipts.jsonl");
      const run = (extra: string[]) => cli(["ledger-anchor", "--log", gated.url, "--log-key", gated.key, "--socket", sock, "--receipts", rc, ...extra]);
      const none = await run([]);
      expect(none.code).toBe(1); expect(none.out).toContain("NOT ANCHORED (refused)"); expect(existsSync(rc)).toBe(false); expect(ours(gated).length).toBe(0);
      const bad = join(dir, "bad.token"); writeFileSync(bad, "not a token\n");
      const unusable = await run(["--token-file", bad]);
      expect(unusable.code).toBe(2); expect(unusable.out).toContain("Nothing was sent");
      const txt = join(dir, "t.token"); writeFileSync(txt, `sigsum-token: ${token}\n`, { mode: 0o600 });
      const withText = await run(["--token-file", txt]);
      expect(withText.out).toContain("ANCHORED — seq 4"); expect(withText.code).toBe(0); expect(withText.out).not.toContain("0f0f0f");
      rmSync(rc); refuse("R-5");
      const json = join(dir, "t.json"); writeFileSync(json, JSON.stringify({ tokens: { elsewhere: { url: "https://other.example", header: "x y" }, here: { url: gated.url + "/", header: `sigsum-token: ${token}` } } }));
      const withJson = await run(["--token-file", json]);
      expect(withJson.out).toContain("ANCHORED — seq 5"); expect(withJson.code).toBe(0); expect(ours(gated).length).toBe(2);
      const wrongLog = await cli(["ledger-anchor", "--log", "http://127.0.0.1:1", "--log-key", gated.key, "--socket", sock, "--receipts", rc, "--token-file", json]);
      expect(wrongLog.code).toBe(2); expect(wrongLog.out).toContain("no entry for");
    } finally { gated.stop(); }
  });

  it("no authority, or no log named, is 'could not ask' (exit 2), never a silent pass", async () => {
    const noLog = await cli(["ledger-anchor", "--socket", sock]); expect(noLog.code).toBe(2);
    const noAuth = await cli(["ledger-anchor", "--log", log.url, "--log-key", log.key, "--socket", join(dir, "nobody.sock")]); expect(noAuth.code).toBe(2);
  });
});

describe("anchor arithmetic, against an independent implementation", () => {
  it("the root and the inclusion proofs agree with a separately written RFC 6962 tree, at awkward sizes", async () => {
    for (const n of [1, 2, 3, 5, 7, 8, 13]) {
      const d = Array.from({ length: n }, () => randomBytes(32));
      expect(merkleRoot(d).toString("hex")).toBe(mth(d).toString("hex"));
      for (let i = 0; i < n; i++) {
        const path = auditPath(i, d).map((h) => h.toString("hex"));
        expect(verifyInclusion(d[i].toString("hex"), i, n, path, mth(d).toString("hex"))).toBe(true);
        if (n > 1) expect(verifyInclusion(d[i].toString("hex"), (i + 1) % n, n, path, mth(d).toString("hex"))).toBe(false);
      }
    }
  });

  it("a ledger row's signature cannot be passed off as an anchor's", async () => {
    const kp = generateLedgerKeypair();
    const row = signLedgerRow({ ts: "t", kind: "refused", gate: "g", rule: null, session: null }, 1, "", kp.privateKey);
    expect(verifyLeafSignature("00".repeat(32), Buffer.from(row.sig, "base64").toString("hex"), kp.publicKey)).toBe(false);
  });
});
