// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// aegis ledger-anchor --log <url> --log-key <hex> [--token-file <path>] — anchor the signed refusal
// ledger in a public transparency log (concealment rung 4; core/ledger-anchor.ts).
//
// It asks the ledger authority for a signed statement of where the ledger stands, checks that
// statement itself, submits it as one leaf, and does not call it done until the log has proven the
// leaf is in a tree head its own key signed. The proof is kept as a line in a receipts file.
//
// WHO HOLDS WHAT. The authority holds the ledger key and signs; it needs no network and no log
// token. This command holds the log's submit token and signs nothing: it cannot make an anchor, it
// can only carry one. Run it once a day, as an account that can read the token.
//
//   --log <url>            the log's base URL                      ($AEGIS_ANCHOR_LOG)
//   --log-key <hex>        the log's Ed25519 public key, 64 hex    ($AEGIS_ANCHOR_LOG_KEY)
//   --token-file <path>    the sigsum submit token                 ($AEGIS_ANCHOR_TOKEN_FILE)
//                          a text file whose first line is "<domain> <hex signature>" (with or without
//                          a leading "sigsum-token:"), or a JSON file {"tokens": {"<name>": {"url", "header"}}}
//                          from which the entry for this log's URL is taken. Never printed.
//   --policy <name|file>   a Sigsum trust policy ($AEGIS_ANCHOR_POLICY): the anchor is not called done until the proof is
//                          against a tree head cosigned by the policy's quorum of witnesses. A name is one of the
//                          published policies in src/core/anchor-policies (sigsum-generic-2025-1 for seasalp).
//                          Without one, only the log's own signature is checked, and the output says so.
//   --socket <path>        the authority's socket (default: where the gates find it)
//   --receipts <path>      where proofs are kept (default <aegis home>/ledger-anchors.jsonl)
//   --dry-run              ask, check and show the statement; send nothing
//
// A ledger that has not grown since its last anchor in this log is not sent again.
//
// Exit: 0 anchored, or already anchored, or the ledger is empty · 1 the log refused or did not prove it
//       2 could not ask (no authority, no log given, token unreadable, or the log could not be reached or did
//         not answer as the log it was named as) · 3 broke (something wrong on this side).

import { appendFileSync, existsSync, mkdirSync, readFileSync } from "fs";
import { homedir } from "os";
import { dirname, join } from "path";
import { askLedgerAuthority } from "../../kavach/approver-client";
import { ledgerSocket } from "../../core/refusal-ledger";
import { loadPolicy, submitAnchor, verifyAnchor, type Anchor, type AnchorReceipt, type TrustPolicy } from "../../core/ledger-anchor";

const norm = (u: string) => u.replace(/\/+$/, "");

/** The sigsum-token header value for this log, from a text or JSON token file. Throws with a reason. */
export function readToken(file: string, logUrl: string): string {
  const raw = readFileSync(file, "utf-8").trim();
  let value: string | undefined;
  if (raw.startsWith("{")) {
    const tokens = (JSON.parse(raw) as { tokens?: Record<string, { url?: string; header?: string }> }).tokens || {};
    value = Object.values(tokens).find((t) => t && typeof t.url === "string" && norm(t.url) === norm(logUrl))?.header;
    if (!value) throw new Error(`the token file has no entry for ${logUrl}`);
  } else value = raw.split("\n")[0];
  value = value.replace(/^sigsum-token:\s*/i, "").trim();
  if (!/^[a-z0-9.-]+ [0-9a-f]{128}$/i.test(value)) throw new Error("the token is not '<domain> <128 hex digits>'");
  return value;
}

export default async function ledgerAnchor(args: string[]): Promise<void> {
  const flag = (n: string) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : undefined; };
  const say = (s: string) => process.stdout.write(`[ledger-anchor] ${s}\n`);
  const fail = (code: number, s: string): never => { process.stderr.write(`[ledger-anchor] ${s}\n`); process.exit(code); };
  try {
    const url = flag("--log") || process.env.AEGIS_ANCHOR_LOG;
    const key = flag("--log-key") || process.env.AEGIS_ANCHOR_LOG_KEY;
    if (!url || !key || !/^[0-9a-f]{64}$/i.test(key)) fail(2, "COULD NOT ANCHOR — give the log (--log <url>) and its public key (--log-key <64 hex>). Nothing was sent.");
    const log = { url: norm(url as string), publicKey: (key as string).toLowerCase() };
    const socket = flag("--socket") || ledgerSocket();
    if (!socket) fail(2, "COULD NOT ANCHOR — no ledger authority is configured (no socket). Only the authority can sign an anchor.");
    const home = process.env.AEGIS_HOME || join(homedir(), ".aegis");
    const receiptsPath = flag("--receipts") || join(home, "ledger-anchors.jsonl");
    const dry = args.includes("--dry-run");
    let policy: TrustPolicy | null = null;
    const policyRef = flag("--policy") || process.env.AEGIS_ANCHOR_POLICY;
    if (policyRef) {
      try {
        const got = loadPolicy(policyRef); policy = got.policy;
        if (!policy.logs.some((l) => l.key === log.publicKey)) throw new Error("it does not name this log's key");
      } catch (e) { fail(2, `COULD NOT ANCHOR — the trust policy could not be used: ${(e as Error).message}. Nothing was sent.`); }
    }

    const st = await askLedgerAuthority<{ max_seq: number; public_key: string; source: string }>(socket as string, "ledger-status");
    if (!st.ok || !st.value) fail(2, `COULD NOT ANCHOR — the authority did not answer: ${st.error ?? "no reply"}`);
    if ((st.value as { max_seq: number }).max_seq === 0) { say("the ledger is empty — nothing to anchor."); process.exit(0); }
    const got = await askLedgerAuthority<Anchor>(socket as string, "anchor");
    if (!got.ok || !got.value) fail(2, `COULD NOT ANCHOR — the authority gave no anchor: ${got.error ?? "no reply"}`);
    const a = got.value as Anchor;
    // Nothing the authority says is carried on trust: the statement is rebuilt and the signature checked.
    if (!verifyAnchor(a, (st.value as { public_key: string }).public_key)) fail(3, "BROKE — the anchor the authority handed over does not verify under its own public key. Nothing was sent.");
    say(`the ledger '${a.source}' stands at seq ${a.max_seq}, tail ${a.tail_hash.slice(0, 16)}…`);

    const receipts: AnchorReceipt[] = existsSync(receiptsPath)
      ? readFileSync(receiptsPath, "utf-8").split("\n").filter(Boolean).flatMap((l) => { try { return [JSON.parse(l) as AnchorReceipt]; } catch { return []; } })
      : [];
    const had = receipts.find((r) => norm(r.log) === log.url && r.leaf_hash === a.leaf_hash);
    if (had) { say(`already anchored: this tail is leaf ${had.leaf_index} of ${log.url} (${had.at}). Nothing was sent.`); process.exit(0); }
    if (dry) { say(`dry run: would submit leaf ${a.leaf_hash} to ${log.url}. Nothing was sent.`); process.exit(0); }

    let token: string | null = null;
    const tokenFile = flag("--token-file") || process.env.AEGIS_ANCHOR_TOKEN_FILE;
    if (tokenFile) {
      try { token = readToken(tokenFile, log.url); }
      catch (e) { fail(2, `COULD NOT ANCHOR — the token file could not be used: ${(e as Error).message}. Nothing was sent.`); }
    } else say("no token file given — submitting without a rate-limit token (a public log is expected to refuse this).");

    const wait = parseInt(process.env.AEGIS_ANCHOR_WAIT_MS || "", 10);   // between tries while the log commits (default 3 s)
    // A log that cannot be reached, is slow, or answers with something that is not its signed tree head is
    // "could not", not "broke": nothing is wrong on this side, and the same command can simply be run again
    // (the leaf is the same, so a request that did get through is not sent twice).
    let out: Awaited<ReturnType<typeof submitAnchor>>;
    try { out = await submitAnchor(log, a, token, { say: (s) => say(s), policy, ...(Number.isFinite(wait) && wait > 0 ? { waitMs: wait } : {}) }); }
    catch (e) { fail(2, `COULD NOT ANCHOR — the log at ${log.url} could not be reached or did not answer as that log: ${(e as Error).message}. Nothing is recorded as anchored; if a request did get through, running this again finishes the job without a second leaf.`); return; }
    if (!out.ok) fail(1, `NOT ANCHORED (${out.kind}) — ${out.detail}`);
    const receipt = (out as { receipt: AnchorReceipt }).receipt;
    mkdirSync(dirname(receiptsPath), { recursive: true });
    appendFileSync(receiptsPath, JSON.stringify(receipt) + "\n");
    say(`ANCHORED — seq ${receipt.max_seq} is leaf ${receipt.leaf_index} in a tree of ${receipt.tree_size}, root ${receipt.root_hash.slice(0, 16)}…, ${receipt.witnessed_by ? `cosigned by ${receipt.witnessed_by.join(", ")} (the policy's quorum '${receipt.quorum}' is met)` : `${receipt.cosignatures} cosignature(s) seen (not checked: no trust policy given)`}.`);
    say(`proof kept in ${receiptsPath}. The receipt is a convenience: \`aegis ledger-verify --anchor-log\` reads the log itself.`);
    process.exit(0);
  } catch (e) {
    fail(3, `BROKE — ${(e as Error).message}`);
  }
}
