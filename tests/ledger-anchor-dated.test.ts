// SPDX-License-Identifier: AGPL-3.0-only
// Dated anchors (aegis 2.17.0): the statement form, what the verifier accepts as a (row, day), and the time
// check against the witnesses. End to end, with real processes and a stand-in log whose clocks are set:
// red-team/ledger-quiet-or-dead.battery.sh.
import { existsSync as _exists } from "fs";
import { describe, expect, test } from "bun:test";
import { createHash, createPublicKey, generateKeyPairSync, sign } from "crypto";
import { createServer } from "net";
import { mkdtempSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { generateLedgerKeypair, signLedgerRow, rowHash, type SignedRow } from "../src/core/ledger-sign";
import {
  anchorStatement, anchorChecksum, signAnchor, verifyAnchor, judgeAnchors, checkLeafTimes, isDay, utcDay, parsePolicy,
  type AnchorReceipt, type DatedLeaf, type LoggedLeaf, type ScanResult,
} from "../src/core/ledger-anchor";

const kp = generateLedgerKeypair();
const S = "unit-box";
const row = (seq: number, prev: string, ts: string): SignedRow => signLedgerRow({ ts, kind: "refused", gate: "g", rule: null, session: null }, seq, prev, kp.privateKey);
const r1 = row(1, "", "2026-03-01T10:00:00.000Z");
const r2 = row(2, rowHash(r1), "2026-03-04T10:00:00.000Z");
const rows = [r1, r2];
const leafOf = (seq: number, day: string | undefined, index: number): LoggedLeaf => {
  const a = signAnchor(S, seq, rowHash(rows[seq - 1]), kp.privateKey, kp.publicKey, day);
  return { index, checksum: a.checksum, signature: a.signature, key_hash: a.key_hash };
};
const scanOf = (leaves: LoggedLeaf[]): ScanResult => ({ head: { size: 100, root_hash: "", signature: "", cosignatures: 0, cosigs: [], checkpoint: "" }, from: 0, leaves, whole_log_checked: true, cosign: null });
const NOW = new Date("2026-03-08T12:00:00Z");

// A box that pins the ledger key at /etc/aegis/ledger-signing.pub pins it for `aegis ledger-anchor` too (since
// 2.17.2 the anchor must be by the pinned key), and it would rightly refuse this file's throwaway authority. There
// these cases are skipped, not failed; the batteries run them in a private mount namespace instead.
const boxPinsAKey = _exists("/etc/aegis/ledger-signing.pub");

describe.skipIf(boxPinsAKey)("the dated statement", () => {
  test("the two forms differ, and a day changes the leaf", () => {
    expect(anchorStatement(S, 1, "h")).toBe('{"anchor":1,"source":"unit-box","max_seq":1,"tail_hash":"h"}');
    expect(anchorStatement(S, 1, "h", "2026-03-01")).toBe('{"anchor":2,"source":"unit-box","max_seq":1,"tail_hash":"h","day":"2026-03-01"}');
    expect(new Set([anchorChecksum(S, 1, "h"), anchorChecksum(S, 1, "h", "2026-03-01"), anchorChecksum(S, 1, "h", "2026-03-02")]).size).toBe(3);
  });
  test("a day is a calendar day and nothing else", () => {
    expect(isDay("2026-03-01")).toBe(true);
    for (const bad of ["2026-3-1", "2026-13-01", "tomorrow", "", '2026-03-01","x":"y', 20260301, null]) expect(isDay(bad)).toBe(false);
    expect(() => signAnchor(S, 1, "h", kp.privateKey, kp.publicKey, "soon")).toThrow();
    expect(utcDay(new Date("2026-03-01T23:59:59Z"))).toBe("2026-03-01");
  });
  test("an anchor verifies only with the day it was signed for", () => {
    const a = signAnchor(S, 1, rowHash(r1), kp.privateKey, kp.publicKey, "2026-03-01");
    expect(verifyAnchor(a, kp.publicKey)).toBe(true);
    expect(verifyAnchor({ ...a, day: "2026-03-02" }, kp.publicKey)).toBe(false);
    const { day: _d, ...undatedLook } = a;
    expect(verifyAnchor(undatedLook, kp.publicKey)).toBe(false);
  });
});

describe.skipIf(boxPinsAKey)("what the verifier accepts as a dated leaf", () => {
  test("row 1 on the days it was the tail; undated leaves beside them", () => {
    const j = judgeAnchors(rows, S, kp.publicKey, scanOf([leafOf(1, undefined, 3), leafOf(1, "2026-03-01", 5), leafOf(1, "2026-03-02", 7), leafOf(1, "2026-03-03", 9), leafOf(2, "2026-03-04", 11), leafOf(2, "2026-03-05", 13), leafOf(2, "2026-03-06", 15), leafOf(2, "2026-03-07", 17)]), NOW);
    expect(j.kind).toBe("anchored");
    if (j.kind !== "anchored") return;
    expect(j.upTo).toBe(2);
    expect(j.dated).toMatchObject({ first: "2026-03-01", last: "2026-03-07", holes: [], silentSince: [] });
  });
  test("row 1 stated for a day when row 2 already existed is a state the file cannot account for", () => {
    const j = judgeAnchors(rows, S, kp.publicKey, scanOf([leafOf(1, "2026-03-06", 5)]), NOW);
    expect(j.kind).toBe("contradicted");
  });
  test("row 2 stated for a day before it was written, likewise", () => {
    expect(judgeAnchors(rows, S, kp.publicKey, scanOf([leafOf(2, "2026-03-02", 5)]), NOW).kind).toBe("contradicted");
  });
  test("holes, silence, the future and a day out of order", () => {
    let j = judgeAnchors(rows, S, kp.publicKey, scanOf([leafOf(1, "2026-03-01", 5), leafOf(2, "2026-03-04", 7)]), NOW);
    expect(j.kind === "anchored" && j.dated).toMatchObject({ holes: ["2026-03-02", "2026-03-03"], silentSince: ["2026-03-05", "2026-03-06", "2026-03-07"] });
    j = judgeAnchors(rows, S, kp.publicKey, scanOf([leafOf(2, "2026-03-07", 5), leafOf(2, "2026-03-12", 7)]), NOW);
    expect(j.kind === "contradicted" && j.future.map((l) => l.day)).toEqual(["2026-03-12"]);
    j = judgeAnchors(rows, S, kp.publicKey, scanOf([leafOf(2, "2026-03-07", 5), leafOf(2, "2026-03-05", 7)]), NOW);
    expect(j.kind === "contradicted" && j.outOfOrder.map((l) => l.day)).toEqual(["2026-03-05"]);
  });
  test("today's leaf not sent yet is not silence", () => {
    const j = judgeAnchors(rows, S, kp.publicKey, scanOf([leafOf(2, "2026-03-07", 5)]), NOW);
    expect(j.kind === "anchored" && j.dated?.silentSince).toEqual([]);
  });
  test("no dated leaf at all: the reading says so", () => {
    const j = judgeAnchors(rows, S, kp.publicKey, scanOf([leafOf(2, undefined, 5)]), NOW);
    expect(j.kind === "anchored" && j.dated).toBe(null);
  });
});

describe.skipIf(boxPinsAKey)("when a dated leaf reached the log", () => {
  const sha = (...b: Uint8Array[]) => { const h = createHash("sha256"); b.forEach((x) => h.update(x)); return h.digest(); };
  const raw = (k: ReturnType<typeof createPublicKey>) => Buffer.from(k.export({ format: "der", type: "spki" })).subarray(-32);
  const logKp = generateKeyPairSync("ed25519"); const logKey = raw(logKp.publicKey);
  const ws = [1, 2, 3].map((i) => { const k = generateKeyPairSync("ed25519"); return { name: `w${i}`, key: raw(k.publicKey).toString("hex"), priv: k.privateKey }; });
  const log = { url: "http://log.test", publicKey: logKey.toString("hex") };
  const policy = parsePolicy(`log ${log.publicKey}\n` + ws.map((w) => `witness ${w.name} ${w.key}\n`).join("") + "group g 2 w1 w2 w3\nquorum g\n");
  const leaf: DatedLeaf = { index: 7, checksum: "aa".repeat(32), seq: 2, day: "2026-03-05" };
  const receipt = (seenIso: string, opts: { size?: number; signers?: number; badLogSig?: boolean } = {}): AnchorReceipt => {
    const size = opts.size ?? 9, root = "11".repeat(32), ts = Math.floor(Date.parse(seenIso) / 1000);
    const checkpoint = `sigsum.org/v1/tree/${sha(logKey).toString("hex")}\n${size}\n${Buffer.from(root, "hex").toString("base64")}\n`;
    return {
      at: seenIso, log: log.url, log_key: log.publicKey, source: S, max_seq: 2, tail_hash: "", statement: "", day: leaf.day,
      checksum: leaf.checksum, signature: "", key_hash: "", leaf_hash: "", leaf_index: leaf.index, tree_size: size, root_hash: root, cosignatures: 3,
      head_signature: sign(null, Buffer.from(opts.badLogSig ? "x" + checkpoint : checkpoint), logKp.privateKey).toString("hex"),
      cosigs: ws.slice(0, opts.signers ?? 3).map((w) => ({ key_hash: sha(Buffer.from(w.key, "hex")).toString("hex"), timestamp: ts, signature: sign(null, Buffer.from(`cosignature/v1\ntime ${ts}\n${checkpoint}`), w.priv).toString("hex") })),
    };
  };
  test("on its own day, or the day after", () => {
    expect(checkLeafTimes([leaf], [receipt("2026-03-05T01:10:00Z")], log, policy)).toMatchObject({ onTime: 1, late: [], noProof: [] });
    expect(checkLeafTimes([leaf], [receipt("2026-03-06T00:05:00Z")], log, policy).onTime).toBe(1);
  });
  test("three days later is late", () => {
    const t = checkLeafTimes([leaf], [receipt("2026-03-08T09:00:00Z")], log, policy);
    expect(t.late.map((l) => l.seen)).toEqual(["2026-03-08"]);
  });
  test("a receipt proves nothing without the quorum, the log's signature, a tree that holds the leaf, or its own head", () => {
    for (const r of [receipt("2026-03-05T01:10:00Z", { signers: 1 }), receipt("2026-03-05T01:10:00Z", { badLogSig: true }), receipt("2026-03-05T01:10:00Z", { size: 7 }), { ...receipt("2026-03-05T01:10:00Z"), cosigs: undefined }, { ...receipt("2026-03-05T01:10:00Z"), leaf_index: 6 }]) {
      expect(checkLeafTimes([leaf], [r as AnchorReceipt], log, policy)).toMatchObject({ onTime: 0, noProof: [leaf] });
    }
    expect(checkLeafTimes([leaf], [], log, policy).noProof.length).toBe(1);
  });
  test("a witness time written into the receipt by hand does not verify", () => {
    const r = receipt("2026-03-08T09:00:00Z"); r.cosigs = (r.cosigs || []).map((c) => ({ ...c, timestamp: Math.floor(Date.parse("2026-03-05T01:00:00Z") / 1000) }));
    expect(checkLeafTimes([leaf], [r], log, policy).noProof.length).toBe(1);
  });
});

describe.skipIf(boxPinsAKey)("aegis ledger-anchor --dated against an authority that does not know the question", () => {
  test("an undated answer is 'could not', and nothing is sent", async () => {
    const dir = mkdtempSync(join(tmpdir(), "aegis-dated-old-")); const sock = join(dir, "old.sock");
    const undated = signAnchor(S, 2, rowHash(r2), kp.privateKey, kp.publicKey);
    const srv = createServer((c) => { let buf = ""; c.on("data", (d) => { buf += d; const nl = buf.indexOf("\n"); if (nl === -1) return; const req = JSON.parse(buf.slice(0, nl)); buf = "";
      c.write(JSON.stringify(req.op === "ledger-status" ? { ok: true, value: { max_seq: 2, public_key: kp.publicKey, source: S } } : { ok: true, value: undated }) + "\n"); c.end(); }); });
    await new Promise<void>((r) => srv.listen(sock, () => r()));
    try {
      const p = Bun.spawn(["bun", new URL("../src/cli/index.ts", import.meta.url).pathname, "ledger-anchor", "--dated", "--log", "http://127.0.0.1:9", "--log-key", "00".repeat(32), "--socket", sock, "--receipts", join(dir, "r.jsonl")], { env: { ...process.env, AEGIS_HOME: dir }, stdout: "pipe", stderr: "pipe" });
      const out = (await new Response(p.stdout).text()) + (await new Response(p.stderr).text());
      expect(await p.exited).toBe(2);
      expect(out).toContain("older than 2.17.0");
    } finally { srv.close(); rmSync(dir, { recursive: true, force: true }); }
  }, 30000);
});
