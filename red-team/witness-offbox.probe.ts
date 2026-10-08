// SPDX-License-Identifier: AGPL-3.0-only
// aegis red-team — off-box WITNESS (concealment rung 3, JieGou finding, 2026-10-08).
//
// Rung 2 can't catch tail truncation or a silent agent, because the on-box record is the only record.
// The witness is an independent holder of the record. This proves it alarms on the things rung 2 and
// the agent itself cannot be trusted to surface: a suppressed row (gap), a silent source (stall), a
// forged row (signature), and — the one rung 2 missed — tail truncation (reconcile against the
// witness's high-water-mark). Drives the real Witness state machine; hermetic (crypto + a clock).
//
// Runs against repo source (public): src/core/witness.ts + src/core/ledger-sign.ts.
import { generateLedgerKeypair, signLedgerRow, rowHash, type LedgerPayload, type SignedRow } from "../src/core/ledger-sign.js";
import { Witness, type Alarm } from "../src/core/witness.js";

let gaps = 0;
const SAFE = (id: string, ok: boolean, detail: string) => { console.log(`  [${ok ? "safe" : "GAP "}] ${id} — ${detail}`); if (!ok) gaps++; };

const { publicKey, privateKey } = generateLedgerKeypair();
const other = generateLedgerKeypair();
const payloads: LedgerPayload[] = [1, 2, 3, 4, 5].map((n) => ({ ts: new Date(2026, 0, 1, 0, 0, n).toISOString(), kind: "refused", gate: "g", rule: `R${n}`, session: "s" }));
function build(ps: LedgerPayload[], priv = privateKey): SignedRow[] {
  const rows: SignedRow[] = []; let prev = "";
  for (let i = 0; i < ps.length; i++) { const r = signLedgerRow(ps[i], i + 1, prev, priv); rows.push(r); prev = rowHash(r); }
  return rows;
}
const rows = build(payloads);
const T0 = 1_000_000;

// 1) contiguous stream → no alarm
{
  const w = new Witness(publicKey, 100);
  let alarm: Alarm | null = null;
  for (let i = 0; i < 3; i++) alarm = w.ingest("agentA", rows[i], T0 + i) ?? alarm;
  SAFE("a contiguous stream raises no alarm", alarm === null && w.highWaterMark("agentA") === 3, "ingest seq 1,2,3 → clean, high-water-mark 3");
}

// 2) a suppressed row (sender skips seq, delivers 1,2 then 4) → gap
{
  const w = new Witness(publicKey, 100);
  w.ingest("agentA", rows[0], T0); w.ingest("agentA", rows[1], T0 + 1);
  const a = w.ingest("agentA", rows[3], T0 + 2); // seq 4, skipping 3
  SAFE("a suppressed row is caught", a !== null && a.kind === "gap", `deliver 1,2 then 4 → ${a ? a.kind : "no alarm(!)"}`);
}

// 3) a forged row (signed by the agent's own, not the authority key) → signature
{
  const w = new Witness(publicKey, 100);
  w.ingest("agentA", rows[0], T0);
  const forged = build(payloads, other.privateKey)[1]; // seq 2, wrong key
  const a = w.ingest("agentA", forged, T0 + 1);
  SAFE("a forged row is caught", a !== null && a.kind === "signature", `a row signed by a non-authority key → ${a ? a.kind : "no alarm(!)"}`);
}

// 4) silence → stall (the agent goes quiet; absence is the alarm)
{
  const w = new Witness(publicKey, 100);
  w.ingest("agentA", rows[0], T0);
  const quiet = w.stale(T0 + 50);   // within window → nothing
  const loud  = w.stale(T0 + 500);  // past the 100ms window → stall
  SAFE("silence past the heartbeat window alarms", quiet.length === 0 && loud.length === 1 && loud[0].kind === "stall", `no alarm at +50ms, stall at +500ms — going quiet is loud`);
}

// 5) THE one rung 2 missed — tail truncation: witness holds 5, on-box ledger now shows 2
{
  const w = new Witness(publicKey, 100);
  for (let i = 0; i < 5; i++) w.ingest("agentA", rows[i], T0 + i);
  const a = w.reconcile("agentA", 2);                 // on-box truncated to seq 2
  const clean = w.reconcile("agentA", 5);             // matching → no alarm
  SAFE("tail truncation is caught by reconcile", a !== null && a.kind === "truncation" && clean === null,
    `witness maxSeq=${w.highWaterMark("agentA")}, on-box=2 → ${a ? a.kind : "no alarm(!)"} (the gap rung 2 could not see)`);
}

console.log(`\n  witness-offbox: ${gaps} gap(s)` + (gaps === 0 ? " — gap / silence / forgery / truncation all alarm ✓" : " (RED until fixed)"));
process.exit(gaps > 0 ? 1 : 0);
