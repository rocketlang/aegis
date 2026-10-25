// SPDX-License-Identifier: AGPL-3.0-only
// ANU-018 (an act says why; a redraft names the draft it replaces), ANU-019 (a declined act stays
// declined) and the outward record. Both outcomes per rule (@rule:guards-assert-both-outcomes).
// Runs under a scratch HOME, as outward-send.test.ts does.
import { describe, it, expect } from "bun:test";
import { mkdtempSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

const HOME = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), "outward-memo-"));
process.env.HOME = HOME;
delete process.env.AEGIS_APPROVER_CONSUME_SOCKET;
delete process.env.AEGIS_APPROVER_APPROVE_SOCKET;
delete process.env.AEGIS_ALLOW_INSECURE_LOCAL_APPROVAL;

const K = await import("../src/kavach/outward");
const { sendPlugin } = await import("../src/kavach/outward-send");
const R = await import("../src/kavach/outward-record");
type SendProposal = import("../src/kavach/outward-send").SendProposal;
type Entry = import("../src/kavach/outward").OutwardLedgerEntry;

const NOW = new Date("2026-10-25T10:00:00Z");
const mandate = (over: Record<string, unknown> = {}) => ({
  id: "send-1", kind: "send", reason: "test", granted_by: "human", granted_at: NOW.toISOString(),
  expires_at: new Date(NOW.getTime() + 86_400_000).toISOString(),
  limits: { identities: ["desk"], recipients: ["ops@known.example"], ask_on_new_recipient: false, ask_always: false, per_lane_per_day: 10, lanes: ["m"], ...over },
});
const mail = (over: Partial<SendProposal> = {}): SendProposal => ({
  channel: "email", lane: "m", from: "desk", to: ["ops@known.example"], subject: "Check", body: "Hello.", ...over,
});
const ctx = (over: Record<string, unknown> = {}) => ({ session_id: "s1", now: NOW, mandates: [mandate()], ledger: [] as Entry[], flowStatus: "valid", ...over }) as any;
const memoEnforced = { ...sendPlugin, memoStage: "enforce" as const };
const ids = (rs: any[]) => rs.map((r) => r.id);

describe("ANU-018 — the act says why", () => {
  it("a reason given: PERMIT, recorded in the decision and the ledger row, and shown to the person", () => {
    const d = K.judgeOutward(memoEnforced, mail({ why: "He asked for the P&L on Tuesday's call." }), ctx());
    expect(d.verdict).toBe("PERMIT");
    expect(d.why).toBe("He asked for the P&L on Tuesday's call.");
    expect(d.shown).toContain("why: He asked for the P&L on Tuesday's call.");
    expect(K.decidedEntry(d, "s1").why).toBe("He asked for the P&L on Tuesday's call.");
  });
  it("no reason, a blank one or one over the limit: REFUSE when enforced", () => {
    for (const why of [undefined, "   ", "x".repeat(K.WHY_MAX + 1)]) {
      const d = K.judgeOutward(memoEnforced, mail({ why }), ctx());
      expect(d.verdict).toBe("REFUSE");
      expect(ids(d.refusals)).toEqual(["ANU-018"]);
      expect(d.why).toBeNull();
    }
  });
  it("send enforces it (promoted 2026-10-25): no reason refuses", () => {
    const d = K.judgeOutward(sendPlugin, mail(), ctx());
    expect([sendPlugin.memoStage, d.verdict, ids(d.refusals)]).toEqual(["enforce", "REFUSE", ["ANU-018"]]);
  });
  it("observe-staged (as spend ships it): no reason is noted, the act still permits and still counts as clean", () => {
    const d = K.judgeOutward({ ...sendPlugin, memoStage: "observe" }, mail(), ctx());
    expect(d.verdict).toBe("PERMIT");
    expect(ids(d.observations)).toEqual(["ANU-018"]);
    expect(K.decidedEntry(d, null).clean).toBe(true);
  });
  it("another observation still makes the act unclean", () => {
    const d = K.judgeOutward({ ...sendPlugin, stage: "observe" }, mail({ to: ["x@stranger.example"] }), ctx());
    expect(K.decidedEntry(d, null).clean).toBe(false);
  });
  it("the reason is part of the proposal: a changed reason is a different hash, so an approval does not carry over", () => {
    expect(K.proposalHash("send", mail({ why: "a" }))).not.toBe(K.proposalHash("send", mail({ why: "b" })));
  });
  it("the reason is never handed to the mailer", () => {
    expect(Object.keys(sendPlugin.handoff(mail({ why: "internal" })))).not.toContain("why");
  });
  it("a refused act still records its reason (no mandate)", () => {
    const d = K.judgeOutward(memoEnforced, mail({ why: "follow-up" }), ctx({ mandates: [] }));
    expect([d.verdict, d.why]).toEqual(["REFUSE", "follow-up"]);
  });
  it("a memo that throws is UNKNOWN", () => {
    const d = K.judgeOutward({ ...memoEnforced, memo: () => { throw new Error("x"); } }, mail({ why: "y" }), ctx());
    expect(d.refusals.map((r: any) => [r.id, r.verdict])).toEqual([["ANU-018", "UNKNOWN"]]);
  });
});

describe("ANU-018 — a redraft names the draft it replaces", () => {
  const first = mail({ why: "w", body: "Draft one." });
  const firstHash = K.proposalHash("send", first);
  const seen = [K.decidedEntry(K.judgeOutward(memoEnforced, first, ctx()), "s1")];
  it("names a draft in the ledger: PERMIT, recorded", () => {
    const d = K.judgeOutward(memoEnforced, mail({ why: "w", body: "Draft two.", supersedes: firstHash }), ctx({ ledger: seen }));
    expect(d.verdict).toBe("PERMIT");
    expect(d.supersedes).toBe(firstHash);
    expect(d.shown).toContain(`redraft of: ${firstHash}`);
  });
  it("an unknown hash, a malformed one, or one of another kind: REFUSE", () => {
    const other = [{ ...seen[0], kind: "spend" }];
    for (const [s, ledger] of [["a".repeat(64), seen], ["not-a-hash", seen], [firstHash, other]] as const) {
      const d = K.judgeOutward(memoEnforced, mail({ why: "w", body: "Draft two.", supersedes: s }), ctx({ ledger }));
      expect(ids(d.refusals)).toEqual(["ANU-018.supersedes"]);
      expect(d.supersedes).toBeNull();
    }
  });
  it("no supersedes: no redraft check at all", () => {
    expect(ids(K.judgeOutward(memoEnforced, mail({ why: "w" }), ctx()).results)).not.toContain("ANU-018.supersedes");
  });
});

const fakeMailer = () => {
  const sent: any[] = [];
  return { sent, effector: { name: "fake", deliver: async (h: any) => { sent.push(h); return { ref: `M${sent.length}` }; } } };
};
const yes = { record: async () => "code1", consume: async () => true };

describe("ANU-019 — a declined act stays declined", () => {
  it("declined: refused before hand-off, even with an approval to consume", async () => {
    const m = fakeMailer();
    const p = mail({ why: "w" });
    const c = ctx({ mandates: [mandate({ ask_always: true })] });
    const d = K.judgeOutward(sendPlugin, p, c);
    const declinedCtx = { ...c, ledger: [K.declinedEntry("send", d.proposal_hash, "wrong tone", null, NOW)] };
    const r = await K.executeOutward(sendPlugin, p, d, m.effector, yes, { fresh: () => declinedCtx, ledger: () => {} });
    expect(r).toMatchObject({ done: false, reason: "ANU-019: the person declined this exact act" });
    expect(m.sent.length).toBe(0);
  });
  it("not declined (or a different act declined): it goes", async () => {
    const m = fakeMailer();
    const p = mail({ why: "w" });
    const c = ctx({ mandates: [mandate({ ask_always: true })] });
    const d = K.judgeOutward(sendPlugin, p, c);
    const other = { ...c, ledger: [K.declinedEntry("send", "b".repeat(64), "no", null, NOW)] };
    expect((await K.executeOutward(sendPlugin, p, d, m.effector, yes, { fresh: () => other, ledger: () => {} })).done).toBe(true);
  });
});

describe("the outward record", () => {
  const at = (min: number) => new Date(NOW.getTime() + min * 60_000).toISOString();
  const row = (event: Entry["event"], h: string, min: number, extra: Partial<Entry> = {}): Entry =>
    ({ ts: at(min), event, kind: "send", session: null, proposal_hash: h, mandate_id: "send-1", budget_key: "lane:m", ...extra });
  const H = (c: string) => c.repeat(64);
  const ledger: Entry[] = [
    // a: asked, approved, sent (judged twice: one act)
    row("decided", H("a"), 0, { verdict: "PERMIT", ask: true, why: "w" }), row("decided", H("a"), 5, { verdict: "PERMIT", ask: true, why: "w" }),
    row("approved", H("a"), 5), row("executed", H("a"), 5),
    // b: asked, declined; c: its redraft, asked, still waiting
    row("decided", H("b"), 10, { verdict: "PERMIT", ask: true }), row("declined", H("b"), 12, { mandate_id: null, budget_key: undefined }),
    row("decided", H("c"), 100, { verdict: "PERMIT", ask: true, why: "w", supersedes: H("b") }),
    // d: asked, never answered; e: refused; f: clean, sent
    row("decided", H("d"), 20, { verdict: "PERMIT", ask: true }),
    row("decided", H("e"), 30, { verdict: "REFUSE", ask: false }),
    row("decided", H("f"), 40, { verdict: "PERMIT", ask: false, clean: true, why: "w" }), row("executed", H("f"), 40),
    // g: asked, then judged again with no ask (mandate widened) and sent: cleared, not lapsed
    row("decided", H("7"), 45, { verdict: "PERMIT", ask: true }), row("decided", H("7"), 47, { verdict: "PERMIT", ask: false }), row("executed", H("7"), 47),
    // a row with no decision before it is not counted
    row("executed", H("9"), 50),
  ];
  const now = new Date(NOW.getTime() + 120 * 60_000);
  it("counts each proposal once and sorts out what the person did", () => {
    const [t] = R.outwardRecord(ledger, { now });
    expect(t).toEqual({ kind: "send", budget_key: "lane:m", proposals: 7, refused: 1, asked: 5, approved: 1, declined: 1, cleared: 1, lapsed: 1, waiting: 1, sent: 3, redrafts: 1, with_why: 3 });
    expect(R.approvalRate(t)).toBeCloseTo(1 / 3);
  });
  it("an ask inside the lapse window is waiting, not lapsed", () => {
    const [t] = R.outwardRecord([row("decided", H("d"), 0, { verdict: "PERMIT", ask: true })], { now: new Date(NOW.getTime() + R.LAPSE_MS - 1) });
    expect([t.waiting, t.lapsed]).toEqual([1, 0]);
    expect(R.approvalRate(t)).toBeNull();
  });
  it("--since drops acts first judged before it", () => {
    const [t] = R.outwardRecord(ledger, { now, since: new Date(NOW.getTime() + 35 * 60_000) });
    expect(t.proposals).toBe(3); // c, f and g
  });
  it("an empty or unreadable ledger is no rows", () => {
    expect(R.outwardRecord([], { now })).toEqual([]);
    expect(R.outwardRecord([{ junk: 1 } as any, null as any], { now })).toEqual([]);
  });
});
