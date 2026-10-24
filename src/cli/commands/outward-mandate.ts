// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// `aegis outward-mandate grant <kind> --reason "..." (--limits '<json>' | --limits-file <path>) [--id ID] [--ttl-hours N]`
// `aegis outward-mandate list [kind]` | `show <id>` | `revoke <id> [--reason "..."]`
//
// The named consent behind an outward act (ANU-012): which kind (send, spend), what limits, why, by
// whom, until when. The only sanctioned writer of outward-mandates.json, a protected source
// (ANU-I-005 refuses hand edits). Granting is a person's act: the shield refuses this command when
// it arrives as a tool call (KAV-101). Revoking is open to anyone: taking consent away gives no power.
//
// Limits are checked by the plug-in's own parser before anything is written, and printed whole, so
// the person sees exactly what they granted. A mandate is a window, never a standing power: default
// 24 hours, at most 14 days. Every grant and revoke is appended to outward-mandates.history.jsonl.

import { appendFileSync, mkdirSync, readFileSync } from "fs";
import { dirname, join } from "path";
import { randomBytes } from "crypto";
import {
  readOutwardMandates, writeOutwardMandates, OUTWARD_MANDATES_FILE, type OutwardMandate,
} from "../../kavach/outward";
import { sendPlugin } from "../../kavach/outward-send";
import { makeSpendPlugin } from "../../kavach/outward-spend";

/** The kinds a mandate can be granted for, and each one's own limits parser. */
export const OUTWARD_KINDS: Record<string, (raw: unknown) => unknown | null> = {
  send: (raw) => sendPlugin.parseLimits(raw),
  spend: (raw) => makeSpendPlugin(() => "").parseLimits(raw),
};

export const historyFile = () => join(dirname(OUTWARD_MANDATES_FILE), "outward-mandates.history.jsonl");
const MAX_TTL_H = 24 * 14;
const by = () => process.env.SUDO_USER || process.env.USER || "human";
const flag = (args: string[], k: string): string | undefined => {
  const i = args.indexOf(k);
  return i >= 0 && args[i + 1] !== undefined && !args[i + 1].startsWith("--") ? args[i + 1] : undefined;
};
const out = (s: string) => process.stdout.write(s);
const fail = (s: string): never => { process.stderr.write(s.endsWith("\n") ? s : s + "\n"); process.exit(1); };

function history(act: "grant" | "revoke", m: OutwardMandate, reason?: string): void {
  mkdirSync(dirname(historyFile()), { recursive: true });
  appendFileSync(historyFile(), JSON.stringify({ at: new Date().toISOString(), act, by: by(), ...(reason ? { reason } : {}), mandate: m }) + "\n", { mode: 0o600 });
}

function describe(m: OutwardMandate): string {
  return `${m.id}  [${m.kind}]  by ${m.granted_by}, "${m.reason}", until ${m.expires_at}\n${JSON.stringify(m.limits, null, 2).replace(/^/gm, "    ")}\n`;
}

/** Plain-words notes on limits that are wider than they may look. */
export function widthNotes(kind: string, limits: any): string[] {
  const notes: string[] = [];
  if (kind === "send") {
    const domains = (limits.recipients as string[]).filter((r) => r.trim().startsWith("@"));
    if (domains.length) notes.push(`${domains.join(", ")} permit ANYONE at ${domains.length > 1 ? "those domains" : "that domain"}.`);
    if (limits.ask_on_new_recipient) notes.push("a recipient not on the list will be asked about, not refused.");
    if (!limits.lanes) notes.push("no lanes named: any lane is allowed.");
    if (limits.attach_from?.length) notes.push(`files may be attached from anywhere under ${limits.attach_from.join(", ")}, subfolders included.`);
  }
  if (kind === "spend") {
    if (limits.ask_above >= limits.per_purchase_cap) notes.push("ask_above is at or over the per-purchase cap: no purchase will ever be asked about.");
    if (limits.ask_on_new_merchant) notes.push("a merchant not on the list will be asked about, not refused.");
  }
  return notes;
}

export default async function outwardMandate(args: string[]): Promise<void> {
  const sub = args[0];

  if (args.includes("--help-limits")) { out(LIMITS_HELP); process.exit(0); }

  if (sub === "list") {
    const kind = args[1] && !args[1].startsWith("--") ? args[1] : undefined;
    const now = Date.now();
    const live = readOutwardMandates().filter((m) => Date.parse(m.expires_at) > now && (!kind || m.kind === kind));
    if (!live.length) { out(`no live outward mandates${kind ? ` for ${kind}` : ""}\n`); process.exit(0); }
    for (const m of live) out(`${m.id}  [${m.kind}]  by ${m.granted_by}, "${m.reason}", until ${m.expires_at}\n`);
    process.exit(0);
  }

  if (sub === "show") {
    const id = args[1];
    if (!id) fail("usage: aegis outward-mandate show <id>");
    const m = readOutwardMandates().find((x) => x.id === id);
    if (!m) fail(`no mandate with id ${id}`);
    out(describe(m!));
    if (Date.parse(m!.expires_at) <= Date.now()) out("EXPIRED: this mandate grants nothing.\n");
    process.exit(0);
  }

  if (sub === "grant") {
    const kind = args[1];
    const usage = `usage: aegis outward-mandate grant <${Object.keys(OUTWARD_KINDS).join("|")}> --reason "..." (--limits '<json>' | --limits-file <path>) [--id ID] [--ttl-hours N]`;
    if (!kind || kind.startsWith("--")) fail(usage);
    const parse = OUTWARD_KINDS[kind];
    if (!parse) fail(`unknown kind '${kind}'. Known: ${Object.keys(OUTWARD_KINDS).join(", ")}`);
    const reason = flag(args, "--reason");
    if (!reason) fail(usage);

    const inline = flag(args, "--limits");
    const file = flag(args, "--limits-file");
    if ((inline ? 1 : 0) + (file ? 1 : 0) !== 1) fail(`give exactly one of --limits or --limits-file\n${usage}`);
    let raw: unknown;
    try { raw = JSON.parse(inline ?? readFileSync(file!, "utf8")); } catch (e: any) { fail(`limits are not readable JSON: ${e?.message ?? e}`); }
    const limits = parse(raw);
    if (!limits) fail(`these limits are not valid for ${kind}; nothing was granted. Compare with: aegis outward-mandate --help-limits`);

    const ttlRaw = flag(args, "--ttl-hours");
    const ttlH = ttlRaw === undefined ? 24 : Number(ttlRaw);
    if (!Number.isFinite(ttlH) || ttlH <= 0 || ttlH > MAX_TTL_H) fail(`--ttl-hours must be a number in (0, ${MAX_TTL_H}]: a mandate is a window, never a standing power`);

    const now = Date.now();
    // A spend mandate carries its own id inside its limits (a cart names it); the two must agree.
    const inner = kind === "spend" ? String((limits as any).mandate_id) : undefined;
    if (inner && flag(args, "--id") && flag(args, "--id") !== inner) fail(`--id ${flag(args, "--id")} differs from limits.mandate_id ${inner}; they must be the same`);
    const id = flag(args, "--id") ?? inner ?? `${kind}-${now.toString(36)}-${randomBytes(3).toString("hex")}`;
    if (!/^[A-Za-z0-9_.-]{1,64}$/.test(id)) fail("--id may use letters, digits, '.', '_' and '-' (1-64)");
    const existing = readOutwardMandates();
    if (existing.some((m) => m.id === id && Date.parse(m.expires_at) > now)) fail(`a live mandate already has id ${id}; revoke it first or choose another id`);

    const m: OutwardMandate = {
      id, kind, limits: limits as Record<string, unknown>, reason: reason!,
      granted_by: by(), granted_at: new Date(now).toISOString(), expires_at: new Date(now + ttlH * 3600e3).toISOString(),
    };
    // Expired mandates are dropped, so a grant also compacts the file.
    writeOutwardMandates([...existing.filter((x) => Date.parse(x.expires_at) > now && x.id !== id), m]);
    history("grant", m);
    out(`mandate granted (${OUTWARD_MANDATES_FILE}):\n${describe(m)}`);
    for (const n of widthNotes(kind, limits)) out(`NOTE: ${n}\n`);
    process.exit(0);
  }

  if (sub === "revoke") {
    const id = args[1];
    if (!id || id.startsWith("--")) fail("usage: aegis outward-mandate revoke <id> [--reason \"...\"]");
    const all = readOutwardMandates();
    const m = all.find((x) => x.id === id);
    if (!m) fail(`no mandate with id ${id}`);
    writeOutwardMandates(all.filter((x) => x.id !== id));
    history("revoke", m!, flag(args, "--reason"));
    out(`mandate revoked: ${id} [${m!.kind}]. An act judged under it is refused at hand-off (it is judged again).\n`);
    process.exit(0);
  }

  fail(`usage: aegis outward-mandate grant|list|show|revoke   (limits: aegis outward-mandate --help-limits)`);
}

export const LIMITS_HELP = `Limits for each kind (JSON). Amounts are whole numbers in the smallest unit (paise, cents).

send:
  { "identities": ["desk-mari8x"],                  sending identities allowed (required)
    "recipients": ["ops@x.example", "@partner.example"],  exact addresses or @domain (required)
    "per_lane_per_day": 10,                          (required)
    "lanes": ["mari8x"],                             optional; absent = any lane
    "ask_on_new_recipient": false,                   optional; true = ask instead of refuse
    "ask_always": false,                             optional; true = every message waits for you
    "attach_from": ["/home/me/outbox"] }             optional; absolute directories files may be attached
                                                     from; absent = no attachments. A proposal names each
                                                     file as {"path", "sha256"}; a changed file is refused.

spend:
  { "mandate_id": "same as --id", "agent_id": "cc:<session>", "currency": "INR",
    "per_purchase_cap": 200000, "period_cap": 1000000, "period_days": 30,
    "merchants": ["bookhaven"], "categories": ["books"],
    "ask_above": 100000, "ask_on_new_merchant": false, "freshness_seconds": 900 }
`;
