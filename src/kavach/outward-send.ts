// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// KAVACH — the send guard: the outward-act plug-in for a message (e-mail first).
// @rule:ANU-I-012 identity named by the mandate; every recipient listed or asked; per-lane daily cap;
//                 declared claims carry proof; the mailer's word list stays with the mailer.
//
// What it does NOT see (say it): claims written into the body that the proposal does not declare;
// whether a listed recipient wants the mail; anything the mailer itself refuses (its word list and
// named exceptions, ankr-mailer.ts RMS-094). The mailer is the effector and still refuses at send.

import { createHash } from "crypto";
import { readFileSync, realpathSync, statSync } from "fs";
import { isAbsolute, sep } from "path";
import type { Claim, OutwardMandate, OutwardPlugin } from "./outward";

/** A file sent with the message. The hash is part of the proposal, so the file judged and approved
 *  is the file sent: it is checked when judged, again before hand-off, and on the copy handed over. */
export interface SendAttachment { path: string; sha256: string }

export const ATTACH_MAX_FILES = 10;
export const ATTACH_MAX_BYTES = 10 * 1024 * 1024;   // each
export const ATTACH_MAX_TOTAL = 20 * 1024 * 1024;   // all together

export const sha256File = (p: string): string => createHash("sha256").update(readFileSync(p)).digest("hex");

/** Why this attachment may not go, or null. The path is resolved (symlinks followed) and must lie
 *  inside one of the mandate's attach_from directories, also resolved. */
export function attachmentProblem(a: SendAttachment, attachFrom: string[]): string | null {
  if (!a || typeof a.path !== "string" || typeof a.sha256 !== "string") return "an attachment needs a path and a sha256";
  if (!isAbsolute(a.path) || /[\r\n\0]/.test(a.path)) return `not an absolute path: ${JSON.stringify(a.path)}`;
  if (!/^[0-9a-f]{64}$/.test(a.sha256)) return `${a.path}: sha256 must be 64 lower-case hex characters`;
  let real: string;
  try { real = realpathSync(a.path); } catch { return `${a.path}: no such file`; }
  const inside = attachFrom.some((d) => {
    let root: string;
    try { root = realpathSync(d); } catch { return false; }
    return real.startsWith(root.endsWith(sep) ? root : root + sep);
  });
  if (!inside) return `${a.path}: not inside a directory this mandate allows files from`;
  const st = statSync(real);
  if (!st.isFile()) return `${a.path}: not a regular file`;
  if (st.size > ATTACH_MAX_BYTES) return `${a.path}: ${st.size} bytes, over the ${ATTACH_MAX_BYTES}-byte limit`;
  if (sha256File(real) !== a.sha256) return `${a.path}: its SHA-256 is not the one in the proposal (the file changed)`;
  return null;
}

export interface SendProposal {
  channel: "email";
  lane: string;
  from: string;              // the sending identity, as the mandate names it
  to: string[];
  cc?: string[];
  bcc?: string[];
  subject: string;
  body: string;
  claims?: Claim[];          // e.g. the outreach hold's claim_ref + proof_url
  attachments?: SendAttachment[];
  why?: string;              // ANU-018: why this message, now; shown to the person, never sent
  supersedes?: string;       // ANU-018: proposal hash of the draft this one replaces
}

export interface SendLimits {
  identities: string[];      // sending identities this mandate allows
  recipients: string[];      // exact addresses or "@domain"
  ask_on_new_recipient: boolean;
  ask_always: boolean;
  per_lane_per_day: number;  // GTM: 10
  lanes?: string[];          // absent = any lane
  attach_from?: string[];    // absolute directories files may be attached from; absent = no attachments
}

export interface SendHandoff { from: string; to: string[]; cc: string[]; bcc: string[]; subject: string; body: string; attachments?: SendAttachment[] }

const ADDR = /^[^\s@<>"',;]+@[^\s@<>"',;]+\.[^\s@<>"',;]+$/;
const lc = (s: string) => s.trim().toLowerCase();
const all = (p: SendProposal) => [...(p.to ?? []), ...(p.cc ?? []), ...(p.bcc ?? [])];

export function onList(addr: string, list: string[]): boolean {
  const a = lc(addr);
  const domain = a.slice(a.lastIndexOf("@"));
  return list.some((e) => { const x = lc(e); return x.startsWith("@") ? domain === x : a === x; });
}

const strings = (v: unknown): v is string[] => Array.isArray(v) && v.every((x) => typeof x === "string");

export const sendPlugin: OutwardPlugin<SendProposal, SendLimits, SendHandoff> = {
  kind: "send",
  law: "ANU-I-012 — send",
  stage: "enforce", // ANU-YK-002: promoted by the founder, 2026-10-16 ("switch send and spend to enforce")

  parseLimits(raw) {
    const r = raw as Partial<SendLimits> | null;
    if (!r || !strings(r.identities) || !r.identities.length || !strings(r.recipients) || !r.recipients.length) return null;
    if (!Number.isSafeInteger(r.per_lane_per_day) || (r.per_lane_per_day as number) < 0) return null;
    if (r.lanes !== undefined && !strings(r.lanes)) return null;
    if (r.attach_from !== undefined && (!strings(r.attach_from) || r.attach_from.some((d) => !isAbsolute(d) || d.trim() === sep))) return null;
    return {
      identities: r.identities, recipients: r.recipients, per_lane_per_day: r.per_lane_per_day as number,
      ask_on_new_recipient: r.ask_on_new_recipient === true, ask_always: r.ask_always === true, lanes: r.lanes,
      ...(r.attach_from ? { attach_from: r.attach_from } : {}),
    };
  },

  pick(p, mandates: OutwardMandate<SendLimits>[]) {
    // Several mandates may name one identity: one per lane, or several in one lane (a standing
    // founder-only mandate beside a batch, seen 23 Oct 2026). Take, among those whose lanes cover
    // this lane, the one that lists EVERY recipient; failing that, one that asks the person about
    // new recipients; failing that, the first for the lane (then the first for the identity), so
    // the recipients or lane rule says why it was refused. One mandate must cover the whole
    // message: recipients split across two grants are never stitched together.
    const mine = mandates.filter((m) => m.limits.identities.some((i) => lc(i) === lc(p.from)));
    const inLane = mine.filter((m) => !m.limits.lanes || m.limits.lanes.some((x) => lc(x) === lc(String(p.lane))));
    const covers = (m: OutwardMandate<SendLimits>) => all(p).every((a) => typeof a === "string" && onList(a, m.limits.recipients));
    return inLane.find(covers) ?? inLane.find((m) => m.limits.ask_on_new_recipient) ?? inLane[0] ?? mine[0] ?? null;
  },

  permissives: [
    {
      id: "ANU-I-012.shape", title: "A well-formed message", law: "ANU-I-012 — send",
      check(p) {
        if (p.channel !== "email") return { verdict: "UNKNOWN", detail: `channel ${String(p.channel)} is not one this guard knows` };
        if (!Array.isArray(p.to) || p.to.length === 0) return { verdict: "REFUSE", detail: "no recipient" };
        const bad = all(p).filter((a) => typeof a !== "string" || !ADDR.test(a.trim()));
        if (bad.length) return { verdict: "REFUSE", detail: `not an address: ${bad.map((b) => JSON.stringify(b)).join(", ")}` };
        // A line break in the subject would let the text write its own mail headers.
        if (typeof p.subject !== "string" || /[\r\n]/.test(p.subject)) return { verdict: "REFUSE", detail: "subject missing or carries a line break" };
        if (typeof p.body !== "string" || !p.body.trim()) return { verdict: "REFUSE", detail: "empty body" };
        if (p.attachments !== undefined && !Array.isArray(p.attachments)) return { verdict: "REFUSE", detail: "attachments must be a list" };
        return { verdict: "PERMIT", detail: `${all(p).length} recipient(s)` };
      },
    },
    {
      id: "ANU-I-012.attachments", title: "Files only from where the mandate allows, exactly as proposed", law: "ANU-I-012 — send",
      check(p, l) {
        const list = p.attachments ?? [];
        if (!list.length) return { verdict: "PERMIT", detail: "no attachment" };
        if (!l.attach_from?.length) return { verdict: "REFUSE", detail: "this mandate does not allow attachments (no attach_from)" };
        if (list.length > ATTACH_MAX_FILES) return { verdict: "REFUSE", detail: `${list.length} files, over the limit of ${ATTACH_MAX_FILES}` };
        const problems = list.map((a) => attachmentProblem(a, l.attach_from!)).filter((x): x is string => !!x);
        if (problems.length) return { verdict: "REFUSE", detail: problems.join("; ") };
        const total = list.reduce((n, a) => n + statSync(realpathSync(a.path)).size, 0);
        if (total > ATTACH_MAX_TOTAL) return { verdict: "REFUSE", detail: `${total} bytes in all, over the ${ATTACH_MAX_TOTAL}-byte limit` };
        return { verdict: "PERMIT", detail: `${list.length} file(s), ${total} bytes, each matching its SHA-256` };
      },
    },
    {
      id: "ANU-I-012.identity", title: "Sending identity named by the mandate", law: "ANU-I-012 / GTM-R-007",
      check(p, l) {
        return l.identities.some((i) => lc(i) === lc(p.from))
          ? { verdict: "PERMIT", detail: `sends as ${p.from}` }
          : { verdict: "REFUSE", detail: `${p.from} is not an identity this mandate names` };
      },
    },
    {
      id: "ANU-I-012.lane", title: "Lane allowed", law: "ANU-I-012 — GTM lanes",
      check(p, l) {
        if (!l.lanes) return { verdict: "PERMIT", detail: "any lane" };
        return l.lanes.includes(p.lane) ? { verdict: "PERMIT", detail: `lane ${p.lane}` } : { verdict: "REFUSE", detail: `lane ${p.lane} is not in this mandate` };
      },
    },
    {
      id: "ANU-I-012.recipients", title: "Every recipient listed, or the person asked", law: "ANU-I-012 — gates never write to real people; warm-first",
      check(p, l) {
        const unlisted = all(p).filter((a) => typeof a === "string" && !onList(a, l.recipients));
        if (unlisted.length === 0) return l.ask_always ? { verdict: "PERMIT", ask: true, detail: "all listed; this mandate asks for every message" } : { verdict: "PERMIT", detail: "all listed" };
        return l.ask_on_new_recipient
          ? { verdict: "PERMIT", ask: true, detail: `not on the list, the person decides: ${unlisted.join(", ")}` }
          : { verdict: "REFUSE", detail: `not on the list: ${unlisted.join(", ")}` };
      },
    },
  ],

  claims: (p) => p.claims ?? [],

  memo: (p) => ({ why: p.why, supersedes: p.supersedes }),
  // memoStage left at observe (ANU-YK-002): a send with no reason is noted, not refused, until the founder promotes it.

  budget: (p, l) => ({ key: `lane:${p.lane}`, units: 1, cap: l.per_lane_per_day, period_ms: 86_400_000 }),

  render(p) {
    const line = (k: string, v?: string[]) => (v && v.length ? `${k}: ${v.join(", ")}\n` : "");
    const files = (p.attachments ?? []).map((a) => `attach: ${a?.path} (sha256 ${String(a?.sha256).slice(0, 16)}…)\n`).join("");
    const memo = (typeof p.why === "string" && p.why.trim() ? `why: ${p.why.trim().replace(/\s+/g, " ")}\n` : "")
      + (typeof p.supersedes === "string" ? `redraft of: ${p.supersedes}\n` : "");
    return `send e-mail · lane ${p.lane}\nfrom: ${p.from}\n${line("to", p.to)}${line("cc", p.cc)}${line("bcc", p.bcc)}subject: ${p.subject}\n${files}${memo}---\n${p.body}`;
  },

  handoff: (p) => ({
    from: p.from, to: [...p.to], cc: [...(p.cc ?? [])], bcc: [...(p.bcc ?? [])], subject: p.subject, body: p.body,
    ...(p.attachments?.length ? { attachments: p.attachments.map((a) => ({ path: a.path, sha256: a.sha256 })) } : {}),
  }),
};
