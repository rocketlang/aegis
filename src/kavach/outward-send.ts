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

import type { Claim, OutwardMandate, OutwardPlugin } from "./outward";

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
}

export interface SendLimits {
  identities: string[];      // sending identities this mandate allows
  recipients: string[];      // exact addresses or "@domain"
  ask_on_new_recipient: boolean;
  ask_always: boolean;
  per_lane_per_day: number;  // GTM: 10
  lanes?: string[];          // absent = any lane
}

export interface SendHandoff { from: string; to: string[]; cc: string[]; bcc: string[]; subject: string; body: string }

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
    return {
      identities: r.identities, recipients: r.recipients, per_lane_per_day: r.per_lane_per_day as number,
      ask_on_new_recipient: r.ask_on_new_recipient === true, ask_always: r.ask_always === true, lanes: r.lanes,
    };
  },

  pick(p, mandates: OutwardMandate<SendLimits>[]) {
    // Several mandates may name one identity (one per lane): take the one whose lanes cover this
    // lane; failing that, the first for the identity, so the lane rule says why it was refused.
    const mine = mandates.filter((m) => m.limits.identities.some((i) => lc(i) === lc(p.from)));
    return mine.find((m) => !m.limits.lanes || m.limits.lanes.some((x) => lc(x) === lc(String(p.lane)))) ?? mine[0] ?? null;
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
        return { verdict: "PERMIT", detail: `${all(p).length} recipient(s)` };
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

  budget: (p, l) => ({ key: `lane:${p.lane}`, units: 1, cap: l.per_lane_per_day, period_ms: 86_400_000 }),

  render(p) {
    const line = (k: string, v?: string[]) => (v && v.length ? `${k}: ${v.join(", ")}\n` : "");
    return `send e-mail · lane ${p.lane}\nfrom: ${p.from}\n${line("to", p.to)}${line("cc", p.cc)}${line("bcc", p.bcc)}subject: ${p.subject}\n---\n${p.body}`;
  },

  handoff: (p) => ({ from: p.from, to: [...p.to], cc: [...(p.cc ?? [])], bcc: [...(p.bcc ?? [])], subject: p.subject, body: p.body }),
};
