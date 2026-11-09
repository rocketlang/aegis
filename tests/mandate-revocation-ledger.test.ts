// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// A revoked mandate signed onto the refusal ledger as a row of its own kind (9 Nov 2026). A real
// LedgerAuthority on a throwaway store signs; nothing here reaches the box's own authority.

import { afterAll, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

const scratchHome = mkdtempSync(join(tmpdir(), "aegis-revocation-ledger-"));
const HOME_BEFORE = process.env.HOME;
const AEGIS_DIR_BEFORE = process.env.AEGIS_DIR;
process.env.HOME = scratchHome;
process.env.AEGIS_DIR = join(scratchHome, ".aegis");
process.env.KAVACHOS_MUDRIKA_SECRET = "test-secret-for-revocation-ledger";
mkdirSync(process.env.AEGIS_DIR, { recursive: true });

const { getAegisDir } = await import("../src/core/config");
const { LedgerAuthority } = await import("../src/core/ledger-authority");
const { checkAuthorityReply } = await import("../src/core/refusal-ledger");
const { verifyLedgerRows } = await import("../src/core/ledger-sign");
const M = await import("../src/kavach/mandate");

const authorities: Array<{ stop(): void }> = [];
afterAll(() => {
  for (const a of authorities) a.stop();
  process.env.HOME = HOME_BEFORE;
  if (AEGIS_DIR_BEFORE === undefined) delete process.env.AEGIS_DIR; else process.env.AEGIS_DIR = AEGIS_DIR_BEFORE;
  rmSync(scratchHome, { recursive: true, force: true });
});

const unsafe = !getAegisDir().startsWith(scratchHome) && !process.env.CI;
if (unsafe) console.warn(`[revocation-ledger] SKIPPED: aegis dir resolves to ${getAegisDir()}, not the scratch HOME; run this file on its own`);

function authority() {
  const la = new LedgerAuthority({ storeDir: mkdtempSync(join(scratchHome, "store-")), log: () => {} });
  authorities.push(la);
  return la;
}
const ledgerRows = (la: InstanceType<typeof LedgerAuthority>) => readFileSync(la.ledgerPath, "utf-8").trim().split("\n").map((l) => JSON.parse(l));
// Asks the way askAuthorityRevocation does, minus the socket, judged under the authority's key.
const askVia = (la: InstanceType<typeof LedgerAuthority>) => (id: string) => {
  const asked = { gate: "mandate", rule: null, kind: "revocation", session: `mdr=${id}` };
  const row = la.record(asked);
  return checkAuthorityReply(asked, "cd".repeat(16), { ok: true, value: { seq: row.seq, row, receipt: la.receipt("cd".repeat(16), row) } }, la.publicKey);
};

describe("the authority's side — a revocation row is its own kind, held to one shape", () => {
  test("signed as kind revocation, never as a refusal, and the ledger still verifies", () => {
    const la = authority();
    const row = la.record({ gate: "mandate", kind: "revocation", session: "mdr=mdr_abc_123" });
    expect(row).toMatchObject({ kind: "revocation", gate: "mandate", rule: null, session: "mdr=mdr_abc_123" });
    expect(verifyLedgerRows(ledgerRows(la), la.publicKey).ok).toBe(true);
    expect(la.status().revocation).toBe(true);
  });

  test("any other shape is refused: no free text gets signed under the revocation kind", () => {
    const la = authority();
    expect(() => la.record({ gate: "mandate", kind: "revocation", session: "mdr=has space" })).toThrow();
    expect(() => la.record({ gate: "mandate", kind: "revocation", session: "revoked by the founder" })).toThrow();
    expect(() => la.record({ gate: "mandate", kind: "revocation", rule: "X", session: "mdr=mdr_a" })).toThrow();
    expect(() => la.record({ gate: "other", kind: "revocation", session: "mdr=mdr_a" })).toThrow();
    expect(() => la.record({ gate: "mandate", kind: "revocation", session: `mdr=${"a".repeat(65)}` })).toThrow();
    expect(!require("fs").existsSync(la.ledgerPath) || readFileSync(la.ledgerPath, "utf-8").trim() === "").toBe(true);
  });

  test("checkAuthorityReply rejects a revocation ask answered with a refusal row (what an older authority signs)", () => {
    const old = authority();
    const asked = { gate: "mandate", rule: null, kind: "revocation", session: "mdr=mdr_a" };
    const row = old.record({ ...asked, kind: "refused" });
    const r = checkAuthorityReply(asked, "ab".repeat(16), { ok: true, value: { seq: row.seq, row, receipt: old.receipt("ab".repeat(16), row) } }, old.publicKey);
    expect(r).toHaveProperty("error");
  });
});

describe("askAuthorityRevocation against a socket that answers like an older authority", () => {
  test("ledger-status without revocation: nothing is sent, only the status was asked", async () => {
    const { askAuthorityRevocation } = await import("../src/core/refusal-ledger");
    const d = mkdtempSync(join(scratchHome, "sock-"));
    const sock = join(d, "consume.sock"), log = join(d, "asked.txt");
    const old = Bun.spawn(["bun", "-e", `
      const fs = require("fs");
      require("net").createServer((s) => s.on("data", (b) => {
        const req = JSON.parse(b.toString().split("\\n")[0]);
        fs.appendFileSync(${JSON.stringify(log)}, req.op + "\\n");
        s.end(JSON.stringify(req.op === "ledger-status" ? { ok: true, value: { rows: 5, receipts: true, bell_book: true } } : { ok: true, value: { seq: 6 } }) + "\\n");
      })).listen(${JSON.stringify(sock)}, () => fs.writeFileSync(${JSON.stringify(log)}, ""));
    `]);
    for (let i = 0; i < 100 && !require("fs").existsSync(log); i++) await Bun.sleep(20);
    const before = process.env.AEGIS_LEDGER_SOCKET;
    process.env.AEGIS_LEDGER_SOCKET = sock;
    try {
      expect((askAuthorityRevocation("mdr_abc") as any).error).toContain("does not sign revocation rows");
    } finally {
      if (before === undefined) delete process.env.AEGIS_LEDGER_SOCKET; else process.env.AEGIS_LEDGER_SOCKET = before;
      old.kill();
    }
    expect(readFileSync(log, "utf-8").trim().split("\n")).toEqual(["ledger-status"]);
  });

  test("a mandate id the ledger cannot carry is refused before anything is asked", async () => {
    const { askAuthorityRevocation } = await import("../src/core/refusal-ledger");
    expect((askAuthorityRevocation("a".repeat(65)) as any).error).toContain("nothing was sent");
  });
});

describe.skipIf(unsafe)("revokeMandate writes the local line either way, and names the signed row", () => {
  test("with an authority that knows the kind: the line carries the row's number and hash; the ledger holds the row", () => {
    const la = authority();
    const m = M.ensureMandateForSession("sess-R1", { trustMask: 1, scopeKey: "aegis" }).mandate!;
    const { signed } = M.revokeMandate(m.mudrika_id, "person", "test", askVia(la));
    expect(signed).toMatchObject({ seq: 1, check: "verified" });
    expect(M.judgeMandate(m)).toBe("revoked");
    const lines = readFileSync(join(getAegisDir(), "mandates", "revoked.jsonl"), "utf-8").trim().split("\n").map((l) => JSON.parse(l));
    const line = lines.find((l) => l.mudrika_id === m.mudrika_id);
    expect(line).toMatchObject({ by: "person", reason: "test", authority_seq: 1, authority_check: "verified" });
    expect(typeof line.authority_row_hash).toBe("string");
    expect(ledgerRows(la)[0]).toMatchObject({ seq: 1, kind: "revocation", gate: "mandate", session: `mdr=${m.mudrika_id}` });
  });

  test("with no authority, or one that refuses: still revoked, and the line says why it is unsigned", () => {
    const m = M.ensureMandateForSession("sess-R2", { trustMask: 1, scopeKey: "aegis" }).mandate!;
    const { signed } = M.revokeMandate(m.mudrika_id, "person", "", () => ({ error: "no ledger authority is configured on this box" }));
    expect(signed).toHaveProperty("error");
    expect(M.judgeMandate(m)).toBe("revoked");
    const m3 = M.ensureMandateForSession("sess-R3", { trustMask: 1, scopeKey: "aegis" }).mandate!;
    M.revokeMandate(m3.mudrika_id, "person", "", () => { throw new Error("boom"); });
    expect(M.judgeMandate(m3)).toBe("revoked");
    const lines = readFileSync(join(getAegisDir(), "mandates", "revoked.jsonl"), "utf-8").trim().split("\n").map((l) => JSON.parse(l));
    expect(lines.find((l) => l.mudrika_id === m.mudrika_id).authority_error).toContain("no ledger authority");
    expect(lines.find((l) => l.mudrika_id === m3.mudrika_id).authority_error).toContain("boom");
  });
});
