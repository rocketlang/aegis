// SPDX-License-Identifier: AGPL-3.0-only
// aegis red-team — refusal-ledger CONCEALMENT (JieGou finding, 2026-10-08).
//
// "A row the refused identity can write is evidence against accidents, not against concealment."
// — Shyan-Ming Perng, JieGou. This proves the sequenced+signed ledger (rung 2) turns an intentional
// edit or deletion from a silent success into a CAUGHT break, against the real verifier.
//
// What it must catch: a suppressed middle row (seq gap), an edited row (bad sig/chain), a forged row
// (bad sig), an unsigned ledger (UNVERIFIABLE, never OK). Honest limit: tail truncation (removing the
// most recent rows) is NOT caught on-box — that needs the off-box high-water-mark (rung 3); reported
// as a note, not a pass.
//
// Hermetic — crypto + arrays, no files/root. Runs against repo source: src/core/ledger-sign.ts.
import { generateLedgerKeypair, signLedgerRow, rowHash, verifyLedgerRows, type LedgerPayload, type SignedRow } from "../src/core/ledger-sign.js";

let gaps = 0;
const SAFE = (id: string, ok: boolean, detail: string) => { console.log(`  [${ok ? "safe" : "GAP "}] ${id} — ${detail}`); if (!ok) gaps++; };
const NOTE = (id: string, detail: string) => console.log(`  [note] ${id} — ${detail}`);

const { publicKey, privateKey } = generateLedgerKeypair();
const payloads: LedgerPayload[] = [1, 2, 3, 4, 5].map((n) => ({
  ts: new Date(Date.now() + n).toISOString(), kind: "refused", gate: "aegis-destructive", rule: `KAV-${n}`, session: `s${n}`,
}));

function build(ps: LedgerPayload[]): SignedRow[] {
  const rows: SignedRow[] = []; let prev = "";
  for (let i = 0; i < ps.length; i++) { const r = signLedgerRow(ps[i], i + 1, prev, privateKey); rows.push(r); prev = rowHash(r); }
  return rows;
}
const ledger = build(payloads);

// 1) control — an intact signed ledger verifies
SAFE("control: an intact signed ledger verifies", verifyLedgerRows(ledger, publicKey).ok === true,
  "5 rows, seq contiguous, chain intact, signatures valid → OK");

// 2) suppress a MIDDLE row (conceal a refusal) → sequence gap
const suppressed = ledger.filter((r) => r.seq !== 3);
const vSup = verifyLedgerRows(suppressed, publicKey);
SAFE("suppressing a row is caught", vSup.ok === false && vSup.kind === "gap",
  `delete the seq-3 refusal → verdict=${vSup.ok ? "OK(!)" : vSup.kind} (concealment detected, not a clean log)`);

// 3) edit a row in place → signature/chain break
const edited = ledger.map((r) => ({ ...r }));
edited[1] = { ...edited[1], rule: "KAV-TAMPERED" };
const vEd = verifyLedgerRows(edited, publicKey);
SAFE("editing a row is caught", vEd.ok === false && (vEd.kind === "signature" || vEd.kind === "chain"),
  `change seq-2's rule → verdict=${vEd.ok ? "OK(!)" : vEd.kind}`);

// 4) forge a row with a DIFFERENT key (the agent's own, not the authority's)
const other = generateLedgerKeypair();
const forged = [...ledger];
forged.push(signLedgerRow({ ts: new Date().toISOString(), kind: "refused", gate: "x", rule: "FORGED", session: "s6" }, 6, rowHash(ledger[4]), other.privateKey));
const vFg = verifyLedgerRows(forged, publicKey);
SAFE("a row signed with another key is caught", vFg.ok === false && vFg.kind === "signature",
  `append a row signed by a non-authority key → verdict=${vFg.ok ? "OK(!)" : vFg.kind}`);

// 5) an unsigned (legacy) ledger is UNVERIFIABLE, never OK
const plain = payloads.map((p) => ({ ...p })); // no seq/sig
const vUn = verifyLedgerRows(plain as unknown[], publicKey);
SAFE("an unsigned ledger reads UNVERIFIABLE, not OK", vUn.ok === false && vUn.kind === "unverifiable",
  `today's plain rows → verdict=${vUn.ok ? "OK(!)" : vUn.kind} (a missing authority never looks clean)`);
SAFE("no public key reads UNVERIFIABLE", (verifyLedgerRows(ledger, null) as any).kind === "unverifiable",
  "verify with no authority public key → unverifiable");

// honest limit: tail truncation is NOT caught on-box (needs the off-box high-water-mark, rung 3)
const truncated = ledger.filter((r) => r.seq !== 5);
const vTr = verifyLedgerRows(truncated, publicKey);
NOTE("tail truncation is NOT caught on-box", `removing the LAST row → verdict=${vTr.ok ? "OK (by design)" : vTr.kind} — detecting this needs the off-box witness that knows the true maxSeq (rung 3); verify returns maxSeq=${vTr.ok ? vTr.maxSeq : "?"} for exactly that comparison`);

console.log(`\n  ledger-concealment: ${gaps} gap(s)` + (gaps === 0 ? " — edit/delete/forge/unsigned all caught ✓" : " (RED until fixed)"));
process.exit(gaps > 0 ? 1 : 0);
