// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// aegis ledger-verify [path] [--witness <url> --source <name>] — "show me the chain is whole."
//
// Answers the auditor's question (Shyan-Ming Perng, JieGou): not just "show me the row" but "show me
// that no row was suppressed, edited or forged." Reads the refusal ledger and the authority PUBLIC key
// and reports the first break — a sequence gap (a suppressed refusal), a chain break or a bad signature
// (an edited/forged row), or UNVERIFIABLE (unsigned/legacy, which never reads as clean).
//
// With --witness the file's last seq is also compared with what the off-box witness holds, which is
// the only way a cut-off tail shows.
//
// Exit: 0 clean · 1 a gap/break (concealment or tamper) · 2 unverifiable · 3 broke.

import { existsSync, readFileSync } from "fs";
import { homedir } from "os";
import { join } from "path";
import { hostname } from "os";
import { verifyLedgerFile, refusalLedgerPath } from "../../core/refusal-ledger";
import { witnessHighWaterMark } from "../../core/witness-client";

function loadPublicKey(): string | null {
  const env = process.env.AEGIS_LEDGER_PUBKEY;
  if (env && env.includes("BEGIN")) return env;
  const file = process.env.AEGIS_LEDGER_PUBKEY_FILE || join(process.env.AEGIS_HOME || join(homedir(), ".aegis"), "ledger-signing.pub");
  try { return existsSync(file) ? readFileSync(file, "utf-8") : null; } catch { return null; }
}

export default async function ledgerVerify(args: string[]): Promise<void> {
  const flag = (n: string) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : undefined; };
  const positional = args.filter((a, i) => !a.startsWith("--") && !(i > 0 && args[i - 1].startsWith("--")));
  const path = positional[0] || refusalLedgerPath();
  const witnessUrl = flag("--witness") || process.env.AEGIS_WITNESS_URL;
  const source = flag("--source") || process.env.AEGIS_LEDGER_SOURCE || hostname();
  const pub = loadPublicKey();
  // No file is not an empty ledger. "0 rows, OK" for a path that does not exist would read as clean.
  if (!existsSync(path)) {
    process.stderr.write(`[ledger-verify] UNVERIFIABLE — no ledger file at ${path}. Nothing was checked.\n`);
    process.exit(2);
  }
  let v;
  try {
    v = verifyLedgerFile(path, pub);
  } catch (e) {
    process.stderr.write(`[ledger-verify] BROKE — ${(e as Error).message}\n`);
    process.exit(3);
  }
  if (v.ok) {
    process.stdout.write(`[ledger-verify] OK — ${v.rows} row(s), seq 1..${v.maxSeq} contiguous, chain intact, signatures valid\n`);
    if (witnessUrl) {
      // The on-box file is whole as far as it goes. Ask the witness how far it should go.
      const held = await witnessHighWaterMark(witnessUrl, source);
      if (held === null) {
        process.stderr.write(`[ledger-verify] UNVERIFIABLE — the witness at ${witnessUrl} could not be asked about '${source}'. Truncation is not ruled out.\n`);
        process.exit(2);
      }
      if (held > v.maxSeq) {
        process.stderr.write(`[ledger-verify] TRUNCATION — this ledger ends at seq ${v.maxSeq}, the witness holds ${held} for '${source}': ${held - v.maxSeq} row(s) removed from the tail.\n`);
        process.exit(1);
      }
      if (held < v.maxSeq) {
        process.stderr.write(`[ledger-verify] GAP at the witness — this ledger ends at seq ${v.maxSeq}, the witness holds ${held} for '${source}': ${v.maxSeq - held} row(s) not delivered.\n`);
        process.exit(1);
      }
      process.stdout.write(`[ledger-verify] the witness holds seq ${held} for '${source}' — the same tail.\n`);
      process.exit(0);
    }
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
