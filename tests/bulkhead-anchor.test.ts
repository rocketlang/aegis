// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// aegis Bulkhead — the bell book anchored through the signed-ledger authority (BLK-T2.2, BLK-020), both ways.
// A real LedgerAuthority on a throwaway store signs; nothing here reaches the box's own authority.

import { afterAll, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

const scratchHome = mkdtempSync(join(tmpdir(), "aegis-bulkhead-anchor-"));
const HOME_BEFORE = process.env.HOME;
const AEGIS_DIR_BEFORE = process.env.AEGIS_DIR;
process.env.HOME = scratchHome;
process.env.AEGIS_DIR = join(scratchHome, ".aegis");
mkdirSync(process.env.AEGIS_DIR, { recursive: true });

const { Bulkhead } = await import("../src/bulkhead/bulkhead");
const { verifyAnchors } = await import("../src/bulkhead/bell-book");
const { LedgerAuthority } = await import("../src/core/ledger-authority");
const { checkAuthorityReply } = await import("../src/core/refusal-ledger");
const { verifyRowSig, verifyLedgerRows } = await import("../src/core/ledger-sign");
const { PERM_STANDARD } = await import("../src/kavach/perm-mask");

const authorities: Array<{ stop(): void }> = [];
afterAll(() => {
  for (const a of authorities) a.stop();
  process.env.HOME = HOME_BEFORE;
  if (AEGIS_DIR_BEFORE === undefined) delete process.env.AEGIS_DIR; else process.env.AEGIS_DIR = AEGIS_DIR_BEFORE;
  rmSync(scratchHome, { recursive: true, force: true });
});

const identity = {
  resolve: (t: any) => (t?.proof ? { agent_id: t.proof, mask: PERM_STANDARD, compartment: t.proof === "a" ? "ca" : "cb", ceiling: PERM_STANDARD } : { error: "unknown" }),
  compartmentOf: (id: string) => ({ compartment: id === "a" ? "ca" : "cb", ceiling: PERM_STANDARD }),
};

function authority() {
  const la = new LedgerAuthority({ storeDir: mkdtempSync(join(scratchHome, "store-")), log: () => {} });
  authorities.push(la);
  return la;
}
// The bulkhead asks the way core/refusal-ledger does, minus the socket: a refusal op with kind bell-book,
// judged by checkAuthorityReply under the authority's key.
function askVia(la: InstanceType<typeof LedgerAuthority>) {
  return (rows: number, head: string) => {
    const asked = { gate: "bulkhead", rule: null, kind: "bell-book", session: `rows=${rows} head=${head}` };
    const row = la.record(asked);
    return checkAuthorityReply(asked, "ab".repeat(16), { ok: true, value: { seq: row.seq, row, receipt: la.receipt("ab".repeat(16), row) } }, la.publicKey);
  };
}
function bulkhead(ask?: any) {
  const dir = mkdtempSync(join(scratchHome, "bh-"));
  writeFileSync(join(dir, "doors.json"), JSON.stringify({ doors: [{ id: "d", from: "ca", to: "cb", kinds: ["FINDING"] }] }));
  const bh = new Bulkhead({ dir, identity, askAnchor: ask });
  bh.send({ proof: "a" }, { to: "b", kind: "FINDING", subject: "s", body: {} });
  return { dir, bh, book: join(dir, "bell-book.jsonl") };
}
const ledgerRows = (la: InstanceType<typeof LedgerAuthority>) => readFileSync(la.ledgerPath, "utf-8").trim().split("\n").map((l) => JSON.parse(l));

describe("the authority's side — a bell-book row is its own kind, held to one shape", () => {
  test("it is signed as kind bell-book, never as a refusal, and the ledger still verifies", () => {
    const la = authority();
    const row = la.record({ gate: "bulkhead", kind: "bell-book", session: `rows=3 head=${"a".repeat(64)}` });
    expect(row).toMatchObject({ kind: "bell-book", gate: "bulkhead", rule: null });
    expect(verifyLedgerRows(ledgerRows(la), la.publicKey).ok).toBe(true);
    expect(la.status().bell_book).toBe(true);
  });
  test("any other shape is refused: free text, a rule, another gate", () => {
    const la = authority();
    expect(() => la.record({ gate: "bulkhead", kind: "bell-book", session: "rows=3 head=hello world" })).toThrow();
    expect(() => la.record({ gate: "bulkhead", kind: "bell-book", rule: "X", session: `rows=3 head=${"a".repeat(64)}` })).toThrow();
    expect(() => la.record({ gate: "other", kind: "bell-book", session: `rows=3 head=${"a".repeat(64)}` })).toThrow();
    expect(() => la.record({ gate: "bulkhead", kind: "bell-book", session: `rows=0 head=${"a".repeat(64)}` })).toThrow();
  });
  test("a refusal is unchanged (kind refused)", () => {
    expect(authority().record({ gate: "check-destructive", rule: "KAV-052" }).kind).toBe("refused");
  });
});

describe("BLK-020 — the bulkhead anchors its head and writes the signed answer into the book", () => {
  test("anchor: the ledger holds the book's head, the book names the ledger row, both verify", () => {
    const la = authority();
    const { bh, book } = bulkhead(askVia(la));
    const r = bh.anchor() as any;
    expect(r).toMatchObject({ ok: true, rows: 1, check: "verified", authority_seq: 1 });
    const checks = verifyAnchors(book, ledgerRows(la), (x) => verifyRowSig(x as any, la.publicKey));
    expect(checks).toEqual([{ authority_seq: 1, rows: 1, holds: true }]);
  });
  test("nothing new since the last anchor: the ledger is not asked", () => {
    const la = authority();
    const { bh } = bulkhead(askVia(la));
    expect((bh.anchor() as any).ok).toBe(true);
    expect(bh.anchor()).toMatchObject({ ok: false, error: expect.stringContaining("nothing new") });
    expect(la.status().rows).toBe(1);
  });
  test("an empty book is not anchored", () => {
    const dir = mkdtempSync(join(scratchHome, "bh-"));
    expect(new Bulkhead({ dir, identity, askAnchor: askVia(authority()) }).anchor()).toMatchObject({ ok: false });
  });
  test("an authority that refuses or is too old: the failure is a row, nothing is claimed", () => {
    const { bh, book } = bulkhead(() => ({ error: "the authority does not sign bell-book rows" }));
    expect(bh.anchor()).toMatchObject({ ok: false });
    expect(readFileSync(book, "utf-8")).toContain('"event":"anchor_failed"');
    expect(readFileSync(book, "utf-8")).not.toContain('"event":"anchored"');
  });
  test("a book rewritten after its anchor no longer matches the ledger", () => {
    const la = authority();
    const { bh, book } = bulkhead(askVia(la));
    bh.anchor();
    const lines = readFileSync(book, "utf-8").trim().split("\n").map((l) => JSON.parse(l));
    lines[0].hash = "f".repeat(64); // a rewrite of row 1 (its own chain re-made would change this hash too)
    writeFileSync(book, lines.map((l) => JSON.stringify(l)).join("\n") + "\n");
    expect(verifyAnchors(book, ledgerRows(la), (x) => verifyRowSig(x as any, la.publicKey))[0]).toMatchObject({ holds: false });
  });
  test("a ledger signed by another key does not hold the anchor", () => {
    const la = authority();
    const { bh, book } = bulkhead(askVia(la));
    bh.anchor();
    const other = authority();
    expect(verifyAnchors(book, ledgerRows(la), (x) => verifyRowSig(x as any, other.publicKey))[0]).toMatchObject({ holds: false, reason: expect.stringContaining("pinned key") });
  });
  test("a ledger without the named row, or with a refusal at that number, does not hold it", () => {
    const la = authority();
    const { bh, book } = bulkhead(askVia(la));
    bh.anchor();
    expect(verifyAnchors(book, [], () => true)[0]).toMatchObject({ holds: false });
    const fake = authority();
    const refusal = fake.record({ gate: "bulkhead", rule: "BLK-013" });
    expect(verifyAnchors(book, [refusal as any], () => true)[0]).toMatchObject({ holds: false, reason: expect.stringContaining("not this book's anchor") });
  });
});

describe("the client refuses to anchor through an authority that does not know the kind", () => {
  test("checkAuthorityReply rejects a bell-book ask answered with a refusal row (what a 2.17.2 authority would sign)", () => {
    const old = authority();
    const asked = { gate: "bulkhead", rule: null, kind: "bell-book", session: `rows=1 head=${"a".repeat(64)}` };
    const row = old.record({ ...asked, kind: "refused" });
    const r = checkAuthorityReply(asked, "ab".repeat(16), { ok: true, value: { seq: row.seq, row, receipt: old.receipt("ab".repeat(16), row) } }, old.publicKey);
    expect(r).toHaveProperty("error");
  });
});

describe("askAuthorityBellBook against a socket that answers like a 2.17.2 authority", () => {
  test("ledger-status without bell_book: nothing is sent, only the status was asked", async () => {
    const { askAuthorityBellBook } = await import("../src/core/refusal-ledger");
    const d = mkdtempSync(join(scratchHome, "sock-"));
    const sock = join(d, "consume.sock"), log = join(d, "asked.txt");
    // The ask blocks this process while it waits, so the old authority runs in a process of its own.
    const old = Bun.spawn(["bun", "-e", `
      const fs = require("fs");
      require("net").createServer((s) => s.on("data", (b) => {
        const req = JSON.parse(b.toString().split("\\n")[0]);
        fs.appendFileSync(${JSON.stringify(log)}, req.op + "\\n");
        s.end(JSON.stringify(req.op === "ledger-status" ? { ok: true, value: { rows: 5, receipts: true } } : { ok: true, value: { seq: 6 } }) + "\\n");
      })).listen(${JSON.stringify(sock)}, () => fs.writeFileSync(${JSON.stringify(log)}, ""));
    `]);
    for (let i = 0; i < 100 && !require("fs").existsSync(log); i++) await Bun.sleep(20);
    const before = process.env.AEGIS_LEDGER_SOCKET;
    process.env.AEGIS_LEDGER_SOCKET = sock;
    try {
      expect((askAuthorityBellBook(1, "a".repeat(64)) as any).error).toContain("does not sign bell-book rows");
    } finally {
      if (before === undefined) delete process.env.AEGIS_LEDGER_SOCKET; else process.env.AEGIS_LEDGER_SOCKET = before;
      old.kill();
    }
    expect(readFileSync(log, "utf-8").trim().split("\n")).toEqual(["ledger-status"]);
  });
});

// Wired: a real authority daemon on its socket, the ask from another process (the ask blocks its own).
// A box that pins its ledger key pins it for this file's gates too, so this is skipped there and run in a
// private mount namespace (unshare -m, a tmpfs over /etc/aegis), like the other wired ledger tests.
const boxPinsAKey = require("fs").existsSync("/etc/aegis/ledger-signing.pub");
describe.skipIf(boxPinsAKey)("wired: aegis bulkhead anchor through a real authority daemon", () => {
  test("the bell-book row lands in the signed ledger as its own kind, verified under the pinned key", async () => {
    const { startApproverDaemon } = await import("../src/kavach/approver-daemon");
    const d = mkdtempSync(join(scratchHome, "wired-"));
    const store = join(d, "authority"), consume = join(d, "consume.sock"), approve = join(d, "approve.sock");
    const daemon = startApproverDaemon({ storeDir: store, consumeSocketPath: consume, approveSocketPath: approve, ledgerSource: "test-box", log: () => {} });
    try {
      const bhDir = join(d, "bulkhead");
      mkdirSync(bhDir);
      writeFileSync(join(bhDir, "doors.json"), JSON.stringify({ doors: [{ id: "d", from: "ca", to: "cb", kinds: ["FINDING"] }] }));
      const script = `
        const { Bulkhead } = await import(${JSON.stringify(join(import.meta.dir, "..", "src/bulkhead/bulkhead.ts"))});
        const id = { resolve: (t) => ({ agent_id: t.proof, mask: 1, compartment: t.proof === "a" ? "ca" : "cb", ceiling: 1 }), compartmentOf: (x) => ({ compartment: x === "a" ? "ca" : "cb", ceiling: 1 }) };
        const bh = new Bulkhead({ dir: ${JSON.stringify(bhDir)}, identity: id });
        bh.send({ proof: "a" }, { to: "b", kind: "FINDING", subject: "s", body: {} });
        console.log(JSON.stringify(bh.anchor()));`;
      const p = Bun.spawn(["bun", "-e", script], {
        stdout: "pipe", stderr: "pipe",
        env: { ...process.env, AEGIS_LEDGER_SOCKET: consume, AEGIS_LEDGER_PUBKEY_FILE: join(store, "ledger-signing.pub") },
      });
      const out = await new Response(p.stdout).text();
      await p.exited;
      expect(JSON.parse(out.trim().split("\n").at(-1)!)).toMatchObject({ ok: true, check: "verified", rows: 1, authority_seq: 1 });
      const ledger = readFileSync(join(store, "refusals.signed.jsonl"), "utf-8").trim().split("\n").map((l) => JSON.parse(l));
      expect(ledger).toHaveLength(1);
      expect(ledger[0]).toMatchObject({ kind: "bell-book", gate: "bulkhead" });
      const pubKey = readFileSync(join(store, "ledger-signing.pub"), "utf-8");
      expect(verifyAnchors(join(bhDir, "bell-book.jsonl"), ledger, (x) => verifyRowSig(x as any, pubKey))).toEqual([{ authority_seq: 1, rows: 1, holds: true }]);
    } finally {
      daemon.stop();
    }
  });
});
