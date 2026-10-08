// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// aegis ledger-verify [path] — "show me the chain is whole."
//
// Answers the auditor's question (Shyan-Ming Perng, JieGou): not just "show me the row" but "show me
// that no row was suppressed, edited or forged." Reads the refusal ledger and the authority PUBLIC key
// and reports the first break — a sequence gap (a suppressed refusal), a chain break or a bad signature
// (an edited/forged row), or UNVERIFIABLE (unsigned/legacy, which never reads as clean).
//
// Exit: 0 clean · 1 a gap/break (concealment or tamper) · 2 unverifiable · 3 broke.

import { existsSync, readFileSync } from "fs";
import { homedir } from "os";
import { join } from "path";
import { verifyLedgerFile, refusalLedgerPath } from "../../core/refusal-ledger";

function loadPublicKey(): string | null {
  const env = process.env.AEGIS_LEDGER_PUBKEY;
  if (env && env.includes("BEGIN")) return env;
  const file = process.env.AEGIS_LEDGER_PUBKEY_FILE || join(process.env.AEGIS_HOME || join(homedir(), ".aegis"), "ledger-signing.pub");
  try { return existsSync(file) ? readFileSync(file, "utf-8") : null; } catch { return null; }
}

export default async function ledgerVerify(args: string[]): Promise<void> {
  const path = args[0] || refusalLedgerPath();
  const pub = loadPublicKey();
  let v;
  try {
    v = verifyLedgerFile(path, pub);
  } catch (e) {
    process.stderr.write(`[ledger-verify] BROKE — ${(e as Error).message}\n`);
    process.exit(3);
  }
  if (v.ok) {
    process.stdout.write(`[ledger-verify] OK — ${v.rows} row(s), seq 1..${v.maxSeq} contiguous, chain intact, signatures valid\n`);
    if (v.rows > 0) {
      process.stdout.write(`[ledger-verify] note: tail truncation (removing the latest rows) is not detectable on-box; ` +
        `an off-box witness compares maxSeq=${v.maxSeq} against the true high-water-mark.\n`);
    }
    process.exit(0);
  }
  if (v.kind === "unverifiable") {
    process.stderr.write(`[ledger-verify] UNVERIFIABLE — ${v.detail}. ` +
      `This ledger cannot be proven whole. Configure the authority key (AEGIS_LEDGER_PUBKEY_FILE) and sign new rows.\n`);
    process.exit(2);
  }
  process.stderr.write(`[ledger-verify] ${v.kind.toUpperCase()} at seq ${v.seq ?? "?"} — ${v.detail}\n` +
    `[ledger-verify] the ledger was tampered or a refusal was concealed.\n`);
  process.exit(1);
}
