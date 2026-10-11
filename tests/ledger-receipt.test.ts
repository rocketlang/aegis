// SPDX-License-Identifier: AGPL-3.0-only
// The authority's answer is checked, and the local copy is compared with the signed ledger (aegis 2.16.3).
// End to end, with real sockets and a real authority: red-team/ledger-fake-authority.battery.sh.
import { describe, expect, test } from "bun:test";
import { generateLedgerKeypair, signLedgerRow, signReceipt, verifyReceipt, isNonce, rowHash, type SignedRow } from "../src/core/ledger-sign";
import { checkAuthorityReply, pinnedLedgerKey } from "../src/core/refusal-ledger";
import { reconcileLocal } from "../src/core/ledger-reconcile";

const kp = generateLedgerKeypair();
const other = generateLedgerKeypair();
const req = { gate: "aegis-destructive", rule: "KAV-001", kind: "refused", session: "s1" };
const nonce = "0123456789abcdef0123456789abcdef";
const rowFor = (r = req, seq = 1, prev = "", key = kp.privateKey): SignedRow =>
  signLedgerRow({ ts: "2026-10-11T00:00:00.000Z", kind: r.kind, gate: r.gate, rule: r.rule, session: r.session }, seq, prev, key);
const good = (row = rowFor(), n = nonce, key = kp.privateKey) => ({ ok: true, value: { seq: row.seq, row, receipt: signReceipt(n, row, key) } });

describe("the authority's answer, checked against a pinned key", () => {
  test("a real answer verifies", () => {
    const a = checkAuthorityReply(req, nonce, good(), kp.publicKey);
    expect(a).toEqual({ seq: 1, check: "verified", row_hash: rowHash(rowFor()) });
  });
  test("a bare number is not a signed row", () => {
    const a = checkAuthorityReply(req, nonce, { ok: true, value: { seq: 42 } }, kp.publicKey);
    expect("error" in a && a.error).toContain("no signed row");
  });
  test("a receipt for another ask, another row, another key, or none", () => {
    const row = rowFor();
    const err = (reply: unknown) => { const a = checkAuthorityReply(req, nonce, reply as never, kp.publicKey); return "error" in a ? a.error : "ACCEPTED"; };
    expect(err(good(row, "f".repeat(32)))).toContain("another ask");
    expect(err({ ok: true, value: { seq: 1, row, receipt: signReceipt(nonce, rowFor(req, 2, "x"), kp.privateKey) } })).toContain("another row");
    expect(err({ ok: true, value: { seq: 1, row, receipt: { ...signReceipt(nonce, row, other.privateKey) } } })).toContain("receipt's signature");
    expect(err({ ok: true, value: { seq: 1, row } })).toContain("no receipt");
    expect(err(good(rowFor(req, 1, "", other.privateKey), nonce, other.privateKey))).toContain("not by that key");
  });
  test("a genuine row for a different refusal, or under a different number", () => {
    const elsewhere = rowFor({ ...req, gate: "aegis-budget" });
    const a = checkAuthorityReply(req, nonce, good(elsewhere), kp.publicKey);
    expect("error" in a && a.error).toContain("not the refusal that was asked for");
    const row = rowFor();
    const b = checkAuthorityReply(req, nonce, { ok: true, value: { seq: 9, row, receipt: signReceipt(nonce, row, kp.privateKey) } }, kp.publicKey);
    expect("error" in b && b.error).toContain("not the number given");
  });
  test("long fields are compared as the authority stores them", () => {
    const long = { ...req, gate: "g".repeat(200), session: "s".repeat(200) };
    const stored = rowFor({ ...long, gate: "g".repeat(80), session: "s".repeat(80) });
    expect(checkAuthorityReply(long, nonce, good(stored), kp.publicKey)).toMatchObject({ check: "verified" });
  });
  test("with no key pinned the answer is accepted and marked unchecked; an error stays an error", () => {
    expect(checkAuthorityReply(req, nonce, { ok: true, value: { seq: 42 } }, null)).toEqual({ seq: 42, check: "unchecked" });
    expect(checkAuthorityReply(req, nonce, { ok: false, error: "disk full" }, null)).toEqual({ error: "disk full" });
    expect(checkAuthorityReply(req, nonce, { ok: false, error: "disk full" }, kp.publicKey)).toEqual({ error: "disk full" });
  });
  test("a pinned key that cannot be read refuses, it does not fall back", () => {
    const a = checkAuthorityReply(req, nonce, good(), "unreadable");
    expect("error" in a && a.error).toContain("could not be read");
    process.env.AEGIS_LEDGER_PUBKEY_FILE = "/nonexistent/key.pub";
    try { expect(pinnedLedgerKey("/nonexistent/system.pub")).toBe("unreadable"); } finally { delete process.env.AEGIS_LEDGER_PUBKEY_FILE; }
  });
  test("a system key wins over the environment", () => {
    const sys = `${import.meta.dir}/fixtures/.pinned-test-${process.pid}.pub`;
    require("fs").writeFileSync(sys, kp.publicKey);
    process.env.AEGIS_LEDGER_PUBKEY = other.publicKey;
    try { expect(pinnedLedgerKey(sys)).toBe(kp.publicKey); } finally { delete process.env.AEGIS_LEDGER_PUBKEY; require("fs").unlinkSync(sys); }
  });
  test("a nonce is hex only, and a receipt does not verify as anything else", () => {
    expect(isNonce(nonce)).toBe(true);
    for (const bad of ["", "abc", "g".repeat(32), '{"seq":1}'.padEnd(32, "0"), 5, null]) expect(isNonce(bad)).toBe(false);
    const r = signReceipt(nonce, rowFor(), kp.privateKey);
    expect(verifyReceipt(r, kp.publicKey)).toBe(true);
    expect(verifyReceipt({ ...r, seq: 2 }, kp.publicKey)).toBe(false);
    expect(verifyReceipt(r, other.publicKey)).toBe(false);
  });
});

describe("the local copy against the signed ledger", () => {
  const r1 = rowFor(req, 1, "");
  const r2 = rowFor({ ...req, session: "s2" }, 2, rowHash(r1));
  const signed = [r1, r2];
  const localOf = (s: SignedRow, extra: Record<string, unknown> = {}) => ({ ts: s.ts, kind: s.kind, gate: s.gate, rule: s.rule, session: s.session, authority_seq: s.seq, ...extra });

  test("honest rows agree", () => {
    const rec = reconcileLocal([localOf(r1, { authority_check: "verified", authority_row_hash: rowHash(r1) }), localOf(r2)], signed);
    expect(rec).toMatchObject({ numbered: 2, verifiedAtWrite: 1, mismatches: [], silent: [], declared: 0 });
  });
  test("a number the authority never gave", () => {
    const rec = reconcileLocal([localOf(r1), { ...localOf(r2), authority_seq: 42 }], signed);
    expect(rec.mismatches.length).toBe(1);
    expect(rec.mismatches[0]).toContain("seq 42");
  });
  test("a real number borrowed for another refusal, a wrong row hash, a number claimed twice", () => {
    expect(reconcileLocal([{ ...localOf(r1), gate: "aegis-shield" }], signed).mismatches[0]).toContain("another refusal");
    expect(reconcileLocal([localOf(r1, { authority_row_hash: "00" })], signed).mismatches[0]).toContain("row hash");
    expect(reconcileLocal([localOf(r1), localOf(r1)], signed).mismatches[0]).toContain("claim seq 1");
  });
  test("no number and no reason: a finding after the ledger's first row, not before it", () => {
    const bare = (ts: string) => ({ ts, kind: "refused", gate: "aegis-shield", rule: null, session: null });
    const rec = reconcileLocal([bare("2026-10-01T00:00:00.000Z"), bare("2026-10-12T00:00:00.000Z"), { ...bare("2026-10-12T00:00:01.000Z"), authority_error: "unreachable" }], signed);
    expect(rec.silent.length).toBe(1);
    expect(rec.declared).toBe(1);
    expect(reconcileLocal([bare("2026-10-12T00:00:00.000Z")], signed, "2026-10-13T00:00:00.000Z").silent.length).toBe(0);
  });
});
