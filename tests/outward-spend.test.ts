// SPDX-License-Identifier: AGPL-3.0-only
// The spend plug-in (ANU-I-013) on the outward kernel, and the kernel's re-judgement before hand-off.
// Both outcomes per rule. The full ASG battery (42 tests) runs against this plug-in from
// /root/agent-spend-guard; these keep aegis able to prove it alone. Scratch HOME, as outward-send.
import { describe, it, expect } from "bun:test";
import { mkdtempSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { createHash } from "crypto";

process.env.HOME = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), "outward-spend-"));
const K = await import("../src/kavach/outward");
const S = await import("../src/kavach/outward-spend");
type Cart = import("../src/kavach/outward-spend").Cart;

const NOW = new Date("2026-10-16T10:00:00Z");
const hash = (c: Cart) => createHash("sha256").update(K.canonical(c)).digest("hex");
const plugin = { ...S.makeSpendPlugin(hash), stage: "enforce" as const };
const limits = (over: Record<string, unknown> = {}) => ({
  mandate_id: "m1", agent_id: "a1", currency: "INR", per_purchase_cap: 200_000, period_cap: 1_000_000, period_days: 30,
  merchants: ["bookhaven", "readmore"], categories: ["books"], ask_above: 100_000, ask_on_new_merchant: false, freshness_seconds: 900, ...over,
});
const mandate = (over = {}) => ({ id: "m1", kind: "spend", limits: limits(over), reason: "t", granted_by: "human", granted_at: NOW.toISOString(), expires_at: new Date(NOW.getTime() + 86_400_000).toISOString() });
const quote = (seller: string, price: number, at = NOW) => ({ url: `https://${seller}.example/b`, seller, sku: "B1", price, read_at: at.toISOString() });
const cart = (over: Partial<Cart> = {}, price = 45_000, seller = "bookhaven", qty = 1): Cart => ({
  cart_id: "c1", mandate_id: "m1", agent_id: "a1", currency: "INR", shipping: 0, total: price * qty,
  lines: [{ sku: "B1", title: "Book", category: "books", merchant: seller, qty, unit_price: price, quote: quote(seller, price) }], ...over,
});
const ctx = (over: Record<string, unknown> = {}) => ({ session_id: null, now: NOW, mandates: [mandate()], ledger: [], flowStatus: "valid", ...over }) as any;
const judge = (c: Cart, x = ctx()) => K.judgeOutward(plugin, c, x);
const first = (d: any) => d.refusals[0]?.detail ?? "";

describe("ANU-I-013 — spend", () => {
  it("within the mandate: PERMIT, no ask", () => {
    const d = judge(cart());
    expect([d.verdict, d.ask]).toEqual(["PERMIT", false]);
  });
  it("over the per-purchase cap: REFUSE (ASG-003)", () => {
    expect(first(judge(cart({}, 90_000, "bookhaven", 3)))).toContain("ASG-003");
  });
  it("a line with no quote, or a quote for another price: REFUSE (ASG-004)", () => {
    const c = cart(); c.lines[0].quote = null;
    expect(first(judge(c))).toContain("ASG-004");
    const d = cart(); d.lines[0].quote = quote("bookhaven", 1);
    expect(first(judge(d))).toContain("ASG-004");
  });
  it("a stale quote asks (ASG-YK-002); a fresh one does not", () => {
    expect(judge(cart(), ctx({ now: new Date(NOW.getTime() + 16 * 60_000) })).asked[0].detail).toContain("ASG-YK-002");
    expect(judge(cart(), ctx({ now: new Date(NOW.getTime() + 14 * 60_000) })).ask).toBe(false);
  });
  it("above the ask threshold asks (ASG-006)", () => {
    expect(judge(cart({}, 150_000)).asked.map((r: any) => r.id)).toContain("ANU-I-013.ask");
  });
  it("an unknown merchant refuses, or asks if the mandate says so (ASG-YK-003)", () => {
    const c = cart({}, 45_000, "stranger-books");
    expect(first(judge(c))).toContain("ASG-YK-003");
    expect(judge(c, ctx({ mandates: [mandate({ ask_on_new_merchant: true })] })).ask).toBe(true);
  });
  it("a fractional amount refuses (ASG-YK-004); a total that is not its lines refuses (ASG-003)", () => {
    expect(first(judge(cart({}, 450.5)))).toContain("ASG-YK-004");
    expect(first(judge(cart({ total: 1 })))).toContain("ASG-003");
  });
  it("best deal: contradicted asks; a cheaper seller not quoted leaves it unproven (ASG-005)", () => {
    const c = cart({ best_deal: { comparison: [quote("bookhaven", 45_000), quote("readmore", 40_000)] } });
    expect(judge(c).ask).toBe(true);
    expect(S.bestDeal(cart({ best_deal: { comparison: [quote("bookhaven", 45_000)] } }), 900, NOW)).toBe("unproven");
    expect(S.bestDeal(cart({ best_deal: { comparison: [quote("bookhaven", 45_000), quote("readmore", 49_900)] } }), 900, NOW)).toBe("proven");
  });
  it("the period cap counts clean decisions and approvals (ASG-YK-001 via ANU-015)", () => {
    const entry = (h: string, event: any) => ({ ts: NOW.toISOString(), event, kind: "spend", session: null, proposal_hash: h, mandate_id: "m1", budget_key: "mandate:m1", units: 45_000, clean: true });
    expect(first(judge(cart(), ctx({ mandates: [mandate({ period_cap: 100_000 })], ledger: [entry("x", "decided"), entry("y", "approved")] })))).toContain("ASG-YK-001");
    expect(judge(cart(), ctx({ mandates: [mandate({ period_cap: 100_000 })], ledger: [entry("x", "decided")] })).verdict).toBe("PERMIT");
  });
  it("the plug-in ships observe (ANU-YK-002)", () => {
    expect(K.judgeOutward(S.makeSpendPlugin(hash), cart({}, 90_000, "bookhaven", 3), ctx()).verdict).toBe("PERMIT");
  });
});

describe("preflight — judged again on fresh state before hand-off (ANU-012, ANU-016)", () => {
  it("unchanged state: ok, with a one-merchant token request and no card field", () => {
    const d = judge(cart());
    const p = K.preflightOutward(plugin, cart(), d, () => ctx());
    expect(p.ok).toBe(true);
    if (p.ok) expect(Object.keys(p.handoff).sort()).toEqual(["amount", "cart_hash", "currency", "merchant"]);
  });
  it("the mandate removed since judging: refused", () => {
    const d = judge(cart());
    expect(K.preflightOutward(plugin, cart(), d, () => ctx({ mandates: [] }))).toMatchObject({ ok: false });
  });
  it("the flow ended since judging: refused with the caller's reason", () => {
    const d = judge(cart());
    expect(K.preflightOutward(plugin, cart(), d, () => ctx({ flowStatus: "revoked", flowDetail: "flow revoked by the person" }))).toEqual({ ok: false, reason: "flow revoked by the person" });
  });
  it("a cart over two merchants cannot be handed off (ASG-001)", () => {
    const c = cart({ merchants: undefined } as any);
    c.lines.push({ ...c.lines[0], sku: "B2", merchant: "readmore", quote: { ...quote("readmore", 45_000), sku: "B2" } });
    c.total = 90_000;
    const d = judge(c);
    expect(d.verdict).toBe("PERMIT");
    const p = K.preflightOutward(plugin, c, d, () => ctx());
    expect(p.ok ? "" : p.reason).toContain("ASG-001");
  });
});
