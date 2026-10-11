// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// aegis ledger-verify [path] [--witness <url> --source <name>] [--local <file>] — "show me the chain is whole."
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
// a cut or rewritten ledger. No anchor found is UNVERIFIABLE for truncation, not clean. An anchor commits to
// the ledger's name: if NO anchor matches under --source but all match under a name found in this box's anchor
// receipts (--receipts, default <aegis home>/ledger-anchors.jsonl), that is said and the exit is 2, not 1.
// With --anchor-policy <name|file> the tree head that was read must also be cosigned by the policy's
// quorum of witnesses; a head without the quorum is UNVERIFIABLE (exit 2). Without a policy only the
// log's own signature is checked, and a note says so.
//
// DATED ANCHORS (2.17.0). An anchor made with `aegis ledger-anchor --dated` says which UTC day it speaks for,
// one a day. From the first dated leaf on, a day with no leaf is named: days the authority has not spoken
// SINCE its last leaf are SILENT SINCE, exit 1; a past day it missed and then came back from is
// UNVERIFIABLE for that day, exit 2 (--anchor-known-holes <day,day> names days a person has already looked at).
// A leaf dated in the future, or for a day earlier than a leaf already before it in the log, exits 1. With
// --anchor-policy the time each dated leaf reached the log is checked on the witnesses' signatures, from the
// tree heads kept in the receipts: late is exit 1, no such head is exit 2.
//
// With --local <file> the gates' own plain copy is compared with this ledger (core/ledger-reconcile.ts):
// a local row that names a number this ledger does not hold, or holds as another refusal, exits 1, and
// so does a local row written after this ledger's first row with no number and no reason
// (--local-since <ISO time> leaves out rows before a known time).
//
// Exit: 0 clean · 1 a gap/break (concealment or tamper) · 2 unverifiable · 3 broke.

import { existsSync, readFileSync } from "fs";
import { homedir } from "os";
import { join } from "path";
import { hostname } from "os";
import { verifyLedgerFile, refusalLedgerPath, PINNED_LEDGER_KEY_PATH } from "../../core/refusal-ledger";
import { witnessHighWaterMark } from "../../core/witness-client";
import { checkLeafTimes, judgeAnchors, loadPolicy, rawPublicKey, scanForKey, type AnchorReceipt } from "../../core/ledger-anchor";
import type { SignedRow } from "../../core/ledger-sign";
import { reconcileLocal } from "../../core/ledger-reconcile";
import { createHash } from "crypto";

// Which key the ledger is checked against, in order: the one the runner names (AEGIS_LEDGER_PUBKEY, or
// AEGIS_LEDGER_PUBKEY_FILE), then the key pinned for this box's gates, then the copy in the aegis home.
// Through 2.17.0 the pinned key was not looked at, so on a box that pins one the default was still the
// home copy, which the gates' own account can write. The source is always said.
function loadPublicKey(): { pem: string | null; from: string } {
  const env = process.env.AEGIS_LEDGER_PUBKEY;
  if (env && env.includes("BEGIN")) return { pem: env, from: "AEGIS_LEDGER_PUBKEY" };
  const read = (f: string): string | null => { try { return existsSync(f) ? readFileSync(f, "utf-8") : null; } catch { return null; } };
  const named = process.env.AEGIS_LEDGER_PUBKEY_FILE;
  if (named) return { pem: read(named), from: named };
  if (existsSync(PINNED_LEDGER_KEY_PATH)) return { pem: read(PINNED_LEDGER_KEY_PATH), from: `${PINNED_LEDGER_KEY_PATH} (pinned)` };
  const home = join(process.env.AEGIS_HOME || join(homedir(), ".aegis"), "ledger-signing.pub");
  return { pem: read(home), from: `${home} — a file the gates' own account can write; name the key with AEGIS_LEDGER_PUBKEY_FILE, or pin it (aegis ledger-pin)` };
}

export default async function ledgerVerify(args: string[]): Promise<void> {
  const flag = (n: string) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : undefined; };
  const positional = args.filter((a, i) => !a.startsWith("--") && !(i > 0 && args[i - 1].startsWith("--")));
  const path = positional[0] || refusalLedgerPath();
  const witnessUrl = flag("--witness") || process.env.AEGIS_WITNESS_URL;
  const source = flag("--source") || process.env.AEGIS_LEDGER_SOURCE || hostname();
  const key = loadPublicKey();
  const pub = key.pem;
  // On stdout: the first line of stderr is what a caller quotes when the check fails.
  if (pub) process.stdout.write(`[ledger-verify] key: ${key.from}\n`);
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
    // The gates' own copy, if one is named: does every number it carries exist in this ledger, as that refusal?
    let localCode = 0;
    const localPath = flag("--local");
    if (args.includes("--local")) {
      try {
        if (!localPath || localPath.startsWith("--")) throw new Error("--local needs the path of the gates' local file (for example ~/.aegis/refusals.jsonl)");
        if (!existsSync(localPath)) throw new Error(`no local file at ${localPath}`);
        const signedRows = readFileSync(path, "utf-8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as SignedRow);
        const localRows = readFileSync(localPath, "utf-8").split("\n").filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } });
        const rec = reconcileLocal(localRows, signedRows, flag("--local-since"));
        for (const m of rec.mismatches) process.stderr.write(`[ledger-verify] LOCAL ROW NOT IN THE SIGNED LEDGER — ${m}. Something other than the authority answered the gate, or one of the two files was changed.\n`);
        if (rec.silent.length) {
          const last = rec.silent[rec.silent.length - 1];
          process.stderr.write(`[ledger-verify] NOT SIGNED AND NOT SAID — ${rec.silent.length} local refusal(s) written after this ledger's first row carry no number and no reason (the latest: ${last.ts}, ${last.gate}). The gate did not ask the authority: it was not configured for that process. If an operator switched it off for that time, pass --local-since <time it was switched back on>.\n`);
        }
        if (rec.mismatches.length || rec.silent.length) localCode = 1;
        else process.stdout.write(`[ledger-verify] the local copy ${localPath} agrees: ${rec.numbered} numbered row(s), each the refusal this ledger holds under that number (${rec.verifiedAtWrite} checked against a pinned key when written).\n`);
        if (rec.declared) process.stdout.write(`[ledger-verify] note: ${rec.declared} local refusal(s) say they were NOT signed, with the reason. They are not in this ledger.\n`);
        process.stdout.write(`[ledger-verify] note: the local file is written by the gates' own account. A refusal removed from it as well would not show here.\n`);
      } catch (e) {
        process.stderr.write(`[ledger-verify] UNVERIFIABLE — the local copy could not be compared: ${(e as Error).message}\n`);
        localCode = 2;
      }
    }
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
          // An anchor commits to the ledger's NAME as well as its row and hash, and the log holds only a hash. So
          // under a wrong --source every genuine anchor looks like a state this file does not contain. Before
          // crying truncation, try the names this box's own receipts say the ledger was anchored under. A receipt
          // is not believed: the anchors are recomputed under that name, and only a full match counts.
          let otherName: string | null = null;
          if (j.matched === 0) {
            const receiptsPath = flag("--receipts") || join(process.env.AEGIS_HOME || join(homedir(), ".aegis"), "ledger-anchors.jsonl");
            const names = new Set<string>();
            try { for (const l of readFileSync(receiptsPath, "utf-8").split("\n")) { if (!l.trim()) continue; try { const s = JSON.parse(l).source; if (typeof s === "string" && s && s !== source) names.add(s); } catch { /* not a receipt line */ } } } catch { /* no receipts here */ }
            for (const name of names) { if (judgeAnchors(rows, name, pub, scan).kind === "anchored") { otherName = name; break; } }
          }
          if (otherName) {
            process.stderr.write(`[ledger-verify] UNVERIFIABLE under the name '${source}' — the public log's ${j.anchors} anchor(s) for this ledger's key match this file under the name '${otherName}' (the name in this box's anchor receipts), and none match under '${source}'. An anchor commits to the ledger's name. Run again with --source ${otherName}. Nothing was found wrong; nothing was checked under the right name.\n`);
            anchorCode = 2;
          } else {
            const nameNote = j.matched === 0 ? ` None of the ${j.anchors} anchor(s) matches this file under the name '${source}': if that is not the name the authority uses (--source, by default the host name), this is the name and not the ledger. If it is the right name, the ledger was rewritten from before its first anchor.` : "";
            if (j.unmatched.length) process.stderr.write(`[ledger-verify] TRUNCATION OR REWRITE — the public log ${anchorLog} holds ${j.unmatched.length} anchor(s) signed by this ledger's key for a state this file does not contain (leaf index ${j.unmatched.map((l) => l.index).join(", ")}). The ledger once stood where this file does not.${nameNote}\n`);
            for (const l of j.future) process.stderr.write(`[ledger-verify] DATED IN THE FUTURE — leaf ${l.index} of ${anchorLog} is this ledger's statement for ${l.day}, a day that has not come. An authority reading its own clock does not sign that: the ledger key was used elsewhere, or a clock is wrong.\n`);
            for (const l of j.outOfOrder) process.stderr.write(`[ledger-verify] DAY FILLED IN LATE — leaf ${l.index} of ${anchorLog} is this ledger's statement for ${l.day}, and it sits in the log AFTER a leaf for a later day. The authority signs for today only: this one was added afterwards.\n`);
            anchorCode = 1;
          }
        } else if (j.kind === "none") {
          process.stderr.write(`[ledger-verify] UNVERIFIABLE — no anchor signed by this ledger's key for '${source}' was found in ${anchorLog}; ${reach}. Truncation is not ruled out.\n`);
          anchorCode = 2;
        } else {
          process.stdout.write(`[ledger-verify] the public log ${anchorLog} holds ${j.anchors} anchor(s) for '${source}', every one a state this file contains; the latest is seq ${j.upTo} (leaf ${j.leafIndex}); ${reach}.\n`);
          if (j.upTo < j.maxSeq) process.stdout.write(`[ledger-verify] note: ${j.maxSeq - j.upTo} row(s) after seq ${j.upTo} are not anchored yet.\n`);
          // Dated anchors: from the first one on, every day is expected to have one.
          const d = j.dated;
          if (!d) process.stdout.write(`[ledger-verify] note: none of these anchors is dated. From the log alone a quiet ledger and a stopped authority look the same (aegis ledger-anchor --dated).\n`);
          else {
            const known = new Set((flag("--anchor-known-holes") || "").split(",").map((x) => x.trim()).filter(Boolean));
            const holes = d.holes.filter((x) => !known.has(x)); const excused = d.holes.filter((x) => known.has(x));
            process.stdout.write(`[ledger-verify] dated anchors: ${d.leaves.length} leaf(s) from ${d.first} to ${d.last} (UTC days)${scan.whole_log_checked ? "" : `, as far as the partial read from index ${scan.from} shows`}.\n`);
            if (excused.length) process.stdout.write(`[ledger-verify] note: no dated anchor for ${excused.join(", ")}: named as known by the caller (--anchor-known-holes).\n`);
            if (holes.length) {
              process.stderr.write(`[ledger-verify] UNVERIFIABLE for ${holes.length} day(s) — no dated anchor for ${holes.join(", ")}. The authority did not state its ledger in the log on those days (it was stopped, the daily run failed, or the log could not be reached) and it has spoken since. A missed day cannot be filled in afterwards.\n`);
              anchorCode = 2;
            }
            if (d.silentSince.length) {
              process.stderr.write(`[ledger-verify] SILENT SINCE ${d.last} — no dated anchor for ${d.silentSince.length} day(s) up to yesterday (${d.silentSince.slice(0, 10).join(", ")}${d.silentSince.length > 10 ? ", …" : ""}). As far as the log shows, the authority has not stated its ledger since ${d.last}: a refusal after that day is in no anchor.\n`);
              anchorCode = 1;
            }
            // when the leaves reached the log, on the witnesses' signatures
            if (!policy) process.stdout.write(`[ledger-verify] note: when each dated leaf reached the log was not checked (no --anchor-policy): each day is the key holder's word.\n`);
            else {
              const receiptsPath = flag("--receipts") || join(process.env.AEGIS_HOME || join(homedir(), ".aegis"), "ledger-anchors.jsonl");
              let receipts: AnchorReceipt[] = [];
              try { receipts = readFileSync(receiptsPath, "utf-8").split("\n").filter(Boolean).flatMap((l) => { try { return [JSON.parse(l) as AnchorReceipt]; } catch { return []; } }); } catch { /* no receipts here */ }
              const t = checkLeafTimes(d.leaves, receipts, { url: anchorLog.replace(/\/+$/, ""), publicKey: anchorKey.toLowerCase() }, policy);
              for (const l of t.late) {
                process.stderr.write(`[ledger-verify] DAY FILLED IN LATE — leaf ${l.leaf.index} is this ledger's statement for ${l.leaf.day}, and the earliest tree head holding it that the policy's witnesses cosigned is from ${l.seen}. The authority signs for today only.\n`);
                anchorCode = 1;
              }
              if (t.noProof.length) {
                process.stderr.write(`[ledger-verify] UNVERIFIABLE as to time for ${t.noProof.length} dated leaf(s) (${t.noProof.slice(0, 10).map((l) => l.day).join(", ")}${t.noProof.length > 10 ? ", …" : ""}) — ${receiptsPath} holds no tree head, cosigned by the policy's quorum, that shows the leaf in the log. Their day is the key holder's word.\n`);
                if (anchorCode === 0) anchorCode = 2;
              }
              if (t.onTime) process.stdout.write(`[ledger-verify] ${t.onTime} dated leaf(s) were in the log on their own day or the day after, by tree heads the policy's witnesses cosigned (kept in ${receiptsPath}).\n`);
            }
          }
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
    const finish = (code: number): never => process.exit(code === 1 || anchorCode === 1 || localCode === 1 ? 1 : Math.max(code, anchorCode, localCode));
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
