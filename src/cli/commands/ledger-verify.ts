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
// With --anchor-log <url> --anchor-log-key <hex> the file is also compared with what a public
// transparency log holds under this ledger's key (core/ledger-anchor.ts). The log is read from index
// 0 and its root rebuilt, unless --anchor-from <index> asks for a partial read, which is faster and
// cannot rule out a leaf the log did not show. An anchor in the log that this file cannot produce is
// a cut or rewritten ledger. No anchor found is UNVERIFIABLE for truncation, not clean.
// With --anchor-policy <name|file> the tree head that was read must also be cosigned by the policy's
// quorum of witnesses; a head without the quorum is UNVERIFIABLE (exit 2). Without a policy only the
// log's own signature is checked, and a note says so.
//
// Exit: 0 clean · 1 a gap/break (concealment or tamper) · 2 unverifiable · 3 broke.

import { existsSync, readFileSync } from "fs";
import { homedir } from "os";
import { join } from "path";
import { hostname } from "os";
import { verifyLedgerFile, refusalLedgerPath } from "../../core/refusal-ledger";
import { witnessHighWaterMark } from "../../core/witness-client";
import { judgeAnchors, loadPolicy, rawPublicKey, scanForKey } from "../../core/ledger-anchor";
import type { SignedRow } from "../../core/ledger-sign";
import { createHash } from "crypto";

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
    // The public log, if one is named. Its finding is combined with the witness's: 1 beats 2 beats 0.
    let anchorCode = 0;
    const anchorLog = flag("--anchor-log") || process.env.AEGIS_ANCHOR_LOG;
    const anchorKey = flag("--anchor-log-key") || process.env.AEGIS_ANCHOR_LOG_KEY;
    if (anchorLog) {
      try {
        if (!anchorKey || !/^[0-9a-f]{64}$/i.test(anchorKey)) throw new Error("--anchor-log needs --anchor-log-key <64 hex>");
        if (!pub) throw new Error("no authority public key");
        const rows = readFileSync(path, "utf-8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as SignedRow);
        const from = parseInt(flag("--anchor-from") || "0", 10) || 0;
        const keyHash = createHash("sha256").update(rawPublicKey(pub)).digest("hex");
        const policyRef = flag("--anchor-policy") || process.env.AEGIS_ANCHOR_POLICY;
        const policy = policyRef ? loadPolicy(policyRef).policy : null;
        const scan = await scanForKey({ url: anchorLog.replace(/\/+$/, ""), publicKey: anchorKey.toLowerCase() }, keyHash, from, () => {}, policy);
        const j = judgeAnchors(rows, source, pub, scan);
        const reach = scan.whole_log_checked
          ? `the whole log (${scan.head.size} leaves) was read and its root rebuilt against the signed tree head`
          : `the log was read from index ${scan.from} of ${scan.head.size} only: a leaf the log did not show is not ruled out`;
        if (j.kind === "contradicted") {
          process.stderr.write(`[ledger-verify] TRUNCATION OR REWRITE — the public log ${anchorLog} holds ${j.unmatched.length} anchor(s) signed by this ledger's key for a state this file does not contain (leaf index ${j.unmatched.map((l) => l.index).join(", ")}). The ledger once stood where this file does not.\n`);
          anchorCode = 1;
        } else if (j.kind === "none") {
          process.stderr.write(`[ledger-verify] UNVERIFIABLE — no anchor signed by this ledger's key for '${source}' was found in ${anchorLog}; ${reach}. Truncation is not ruled out.\n`);
          anchorCode = 2;
        } else {
          process.stdout.write(`[ledger-verify] the public log ${anchorLog} holds ${j.anchors} anchor(s) for '${source}', every one a state this file contains; the latest is seq ${j.upTo} (leaf ${j.leafIndex}); ${reach}.\n`);
          if (j.upTo < j.maxSeq) process.stdout.write(`[ledger-verify] note: ${j.maxSeq - j.upTo} row(s) after seq ${j.upTo} are not anchored yet.\n`);
        }
        // the witnesses: said for every outcome, and a head without the quorum cannot be called clean
        if (!scan.cosign) process.stdout.write(`[ledger-verify] note: the tree head carries ${scan.head.cosignatures} cosignature(s); they were not checked (no --anchor-policy), only the log's own signature.\n`);
        else if (scan.cosign.met) process.stdout.write(`[ledger-verify] the tree head is cosigned by ${scan.cosign.witnessed.join(", ") || "no witness (the policy asks for none)"}: the policy's quorum '${scan.cosign.quorum}' is met.\n`);
        else {
          process.stderr.write(`[ledger-verify] UNVERIFIABLE — the tree head is NOT cosigned by the policy's quorum '${scan.cosign.quorum}' (verified: ${scan.cosign.witnessed.join(", ") || "none"}; ${scan.cosign.invalid} did not verify; ${scan.cosign.unknown} by keys the policy does not name). What the log showed is not vouched for by its witnesses.\n`);
          if (anchorCode === 0) anchorCode = 2;
        }
      } catch (e) {
        process.stderr.write(`[ledger-verify] UNVERIFIABLE — the public log could not be read: ${(e as Error).message}. Truncation is not ruled out.\n`);
        anchorCode = 2;
      }
    }
    const finish = (code: number): never => process.exit(code === 1 || anchorCode === 1 ? 1 : Math.max(code, anchorCode));
    if (witnessUrl) {
      // The on-box file is whole as far as it goes. Ask the witness how far it should go.
      const held = await witnessHighWaterMark(witnessUrl, source);
      if (held === null) {
        process.stderr.write(`[ledger-verify] UNVERIFIABLE — the witness at ${witnessUrl} could not be asked about '${source}'. Truncation is not ruled out.\n`);
        finish(2);
      }
      if (held > v.maxSeq) {
        process.stderr.write(`[ledger-verify] TRUNCATION — this ledger ends at seq ${v.maxSeq}, the witness holds ${held} for '${source}': ${held - v.maxSeq} row(s) removed from the tail.\n`);
        finish(1);
      }
      if (held < v.maxSeq) {
        process.stderr.write(`[ledger-verify] GAP at the witness — this ledger ends at seq ${v.maxSeq}, the witness holds ${held} for '${source}': ${v.maxSeq - held} row(s) not delivered.\n`);
        finish(1);
      }
      process.stdout.write(`[ledger-verify] the witness holds seq ${held} for '${source}' — the same tail.\n`);
      finish(0);
    }
    if (v.rows > 0 && !anchorLog) {
      process.stdout.write(`[ledger-verify] note: tail truncation (removing the latest rows) is not detectable on-box; ` +
        `an off-box witness compares maxSeq=${v.maxSeq} against the true high-water-mark.\n`);
    }
    finish(0);
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
