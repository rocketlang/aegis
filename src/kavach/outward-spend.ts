// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// KAVACH — the spend guard: the outward-act plug-in for a purchase (a cart).
// @rule:ANU-I-013 compiles the agent-spend-guard rules (ASG-001..008, ASG-YK-001..004) onto the kernel.
//
// Every detail starts with the ASG rule it enforces (ANU-006: cite the law compiled). Amounts are
// whole numbers in the smallest unit (paise, cents). The guard never holds money or a card: the
// hand-off is a token request for one merchant and one amount (ASG-001), and the rail holds the card.
// What it does NOT see: whether a quoted price is fair, or the seller honest — only that the price on
// the cart is the price the quoted page showed, at the time it was read.

import type { OutwardPlugin } from "./outward";

export interface Quote { url: string; seller: string; sku: string; price: number; read_at: string }
export interface CartLine { sku: string; title: string; category: string; merchant: string; qty: number; unit_price: number; quote: Quote | null }
export interface Cart {
  cart_id: string;
  mandate_id: string;
  agent_id: string;
  currency: string;
  lines: CartLine[];
  shipping: number;
  total: number;                      // the agent's figure; recomputed here
  best_deal?: { comparison: Quote[] };
  why?: string;                       // ANU-018: why this purchase, now; shown to the person
  supersedes?: string;                // ANU-018: proposal hash of the cart this one replaces
}

export interface SpendLimits {
  mandate_id: string;
  agent_id: string;
  currency: string;
  per_purchase_cap: number;
  period_cap: number;
  period_days: number;
  merchants: string[];
  categories: string[];
  ask_above: number;
  ask_on_new_merchant: boolean;
  freshness_seconds: number;
}

export interface SpendHandoff { merchant: string; amount: number; currency: string; cart_hash: string }

export type BestDeal = "proven" | "unproven" | "contradicted" | "not-claimed";

const ints = (c: Cart) => [c.shipping, c.total, ...(c.lines ?? []).flatMap((l) => [l.qty, l.unit_price])];
const isWhole = (n: unknown) => Number.isSafeInteger(n) && (n as number) >= 0;
export const cartTotal = (c: Cart) => c.lines.reduce((s, l) => s + l.qty * l.unit_price, 0) + c.shipping;
const ageS = (iso: string, now: Date) => (now.getTime() - Date.parse(iso)) / 1000;

/** ASG-005: proven only on a quoted comparison of at least two sellers; otherwise unproven, never asserted. */
export function bestDeal(cart: Cart, freshnessSeconds: number, now: Date): BestDeal {
  if (!cart.best_deal) return "not-claimed";
  const fresh = cart.best_deal.comparison.filter((q) => q.url && q.read_at && ageS(q.read_at, now) <= freshnessSeconds);
  for (const l of cart.lines) {
    const others = fresh.filter((q) => q.sku === l.sku && q.seller !== l.merchant);
    if (others.some((q) => q.price < l.unit_price)) return "contradicted";
    if (others.length === 0) return "unproven";
  }
  return "proven";
}

const strs = (v: unknown): v is string[] => Array.isArray(v) && v.every((x) => typeof x === "string");

export function makeSpendPlugin(cartHash: (c: Cart) => string): OutwardPlugin<Cart, SpendLimits, SpendHandoff> {
  return {
    kind: "spend",
    law: "ANU-I-013 — spend (agent-spend-guard ASG-001..008)",
    stage: "enforce", // ANU-YK-002: promoted by the founder, 2026-10-16 ("switch send and spend to enforce")

    parseLimits(raw) {
      const r = raw as Partial<SpendLimits> | null;
      if (!r || typeof r.mandate_id !== "string" || typeof r.agent_id !== "string" || typeof r.currency !== "string") return null;
      for (const k of ["per_purchase_cap", "period_cap", "period_days", "ask_above", "freshness_seconds"] as const) if (!isWhole(r[k])) return null;
      if (!strs(r.merchants) || !strs(r.categories)) return null;
      return { ...(r as SpendLimits), ask_on_new_merchant: r.ask_on_new_merchant === true };
    },

    pick: (c, ms) => ms.find((m) => m.limits.mandate_id === c.mandate_id) ?? null,

    // Order matters only for which reason is read first; every check runs.
    permissives: [
      {
        id: "ANU-I-013.whole", title: "Whole amounts in the smallest unit", law: "ASG-YK-004",
        check: (c) => ints(c).every(isWhole) ? { verdict: "PERMIT", detail: "whole amounts" }
          : { verdict: "REFUSE", detail: "ASG-YK-004: an amount is not a whole number in the smallest unit" },
      },
      {
        id: "ANU-I-013.mandate", title: "Cart under this mandate, agent and currency", law: "ASG-002",
        check(c, l) {
          if (c.mandate_id !== l.mandate_id) return { verdict: "REFUSE", detail: "ASG-002: cart names another mandate" };
          if (c.agent_id !== l.agent_id) return { verdict: "REFUSE", detail: "ASG-002: cart is from an agent this mandate does not name" };
          if (c.currency !== l.currency) return { verdict: "REFUSE", detail: `ASG-002: currency ${c.currency} is not ${l.currency}` };
          return { verdict: "PERMIT", detail: "mandate, agent and currency match" };
        },
      },
      {
        id: "ANU-I-013.total", title: "The cart's total is its lines", law: "ASG-003",
        check(c) {
          if (!c.lines?.length) return { verdict: "REFUSE", detail: "ASG-003: empty cart" };
          if (!ints(c).every(isWhole)) return { verdict: "UNKNOWN", detail: "ASG-YK-004: total not computable" };
          const t = cartTotal(c);
          return t === c.total ? { verdict: "PERMIT", detail: `total ${t}` } : { verdict: "REFUSE", detail: `ASG-003: cart says ${c.total}, its lines add to ${t}` };
        },
      },
      {
        id: "ANU-I-013.quotes", title: "Every line carries its quote, fresh", law: "ASG-004 / ASG-YK-002",
        check(c, l, { now }) {
          const missing = c.lines.filter((x) => !x.quote).map((x) => x.sku);
          if (missing.length) return { verdict: "REFUSE", detail: `ASG-004: ${missing.join(", ")} has no quote` };
          const off = c.lines.filter((x) => x.quote!.price !== x.unit_price || x.quote!.seller !== x.merchant || x.quote!.sku !== x.sku).map((x) => x.sku);
          if (off.length) return { verdict: "REFUSE", detail: `ASG-004: ${off.join(", ")} does not match its quote` };
          const stale = c.lines.filter((x) => ageS(x.quote!.read_at, now) > l.freshness_seconds).map((x) => x.sku);
          return stale.length ? { verdict: "PERMIT", ask: true, detail: `ASG-YK-002: quote for ${stale.join(", ")} is older than ${l.freshness_seconds}s` }
            : { verdict: "PERMIT", detail: "every line quoted and fresh" };
        },
      },
      {
        id: "ANU-I-013.merchants", title: "Merchants on the list", law: "ASG-YK-003",
        check(c, l) {
          const unknown = [...new Set(c.lines.map((x) => x.merchant).filter((m) => !l.merchants.includes(m)))];
          if (!unknown.length) return { verdict: "PERMIT", detail: "every merchant listed" };
          const detail = `ASG-YK-003: ${unknown.join(", ")} is not on the merchant list`;
          return l.ask_on_new_merchant ? { verdict: "PERMIT", ask: true, detail } : { verdict: "REFUSE", detail };
        },
      },
      {
        id: "ANU-I-013.categories", title: "Categories allowed", law: "ASG-003",
        check(c, l) {
          const bad = [...new Set(c.lines.map((x) => x.category).filter((k) => !l.categories.includes(k)))];
          return bad.length ? { verdict: "REFUSE", detail: `ASG-003: category ${bad.join(", ")} is not allowed` } : { verdict: "PERMIT", detail: "categories allowed" };
        },
      },
      {
        id: "ANU-I-013.cap", title: "Within the per-purchase cap", law: "ASG-003",
        check(c, l) {
          if (!ints(c).every(isWhole)) return { verdict: "UNKNOWN", detail: "ASG-YK-004: total not computable" };
          const t = cartTotal(c);
          return t > l.per_purchase_cap ? { verdict: "REFUSE", detail: `ASG-003: ${t} is over the per-purchase cap ${l.per_purchase_cap}` }
            : { verdict: "PERMIT", detail: `${t} within ${l.per_purchase_cap}` };
        },
      },
      {
        id: "ANU-I-013.ask", title: "Above the ask-me threshold, the person decides", law: "ASG-006",
        check(c, l) {
          const t = ints(c).every(isWhole) ? cartTotal(c) : 0;
          return t > l.ask_above ? { verdict: "PERMIT", ask: true, detail: `ASG-006: ${t} is above the ask-me threshold ${l.ask_above}` }
            : { verdict: "PERMIT", detail: `${t} within the ask-me threshold` };
        },
      },
      {
        id: "ANU-I-013.best-deal", title: "A best-deal claim is not contradicted by its own quotes", law: "ASG-005",
        check(c, l, { now }) {
          const b = bestDeal(c, l.freshness_seconds, now);
          return b === "contradicted" ? { verdict: "PERMIT", ask: true, detail: "ASG-005: a quoted comparison is cheaper than the chosen seller" }
            : { verdict: "PERMIT", detail: `best deal: ${b}` };
        },
      },
    ],

    // ASG-YK-001: the period cap counts paid plus approved-not-paid (ANU-015 does the counting).
    budget: (c, l) => ({ key: `mandate:${l.mandate_id}`, units: ints(c).every(isWhole) ? cartTotal(c) : 0, cap: l.period_cap, period_ms: l.period_days * 86_400_000, law: "ASG-YK-001" }),

    memo: (c) => ({ why: c.why, supersedes: c.supersedes }),
    // memoStage left at observe (ANU-YK-002): spend has no live caller yet; the founder promotes it.

    render(c) {
      const lines = c.lines.map((x) => `  ${x.qty} × ${x.title} (${x.sku}) from ${x.merchant} @ ${x.unit_price} — quote ${x.quote?.url ?? "NONE"}`).join("\n");
      const memo = (typeof c.why === "string" && c.why.trim() ? `\n  why: ${c.why.trim().replace(/\s+/g, " ")}` : "")
        + (typeof c.supersedes === "string" ? `\n  redraft of: ${c.supersedes}` : "");
      return `spend · cart ${c.cart_id} · mandate ${c.mandate_id} · agent ${c.agent_id}\n${lines}\n  shipping ${c.shipping}\n  total ${c.total} ${c.currency}${memo}`;
    },

    // ASG-001: a token request for one merchant and one amount.
    handoff(c) {
      const merchants = [...new Set(c.lines.map((x) => x.merchant))];
      if (merchants.length !== 1) throw new Error("ASG-001: a payment token is scoped to one merchant; split the cart");
      return { merchant: merchants[0], amount: c.total, currency: c.currency, cart_hash: cartHash(c) };
    },
  };
}
