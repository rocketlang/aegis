// SPDX-License-Identifier: AGPL-3.0-only
// The outward-act kernel (ANU-011..017, ANU-YK-002) and the send guard (ANU-I-012).
// Both outcomes per rule (@rule:guards-assert-both-outcomes). Runs under a scratch HOME: the
// modules are imported only after HOME is set, so the box's own ~/.aegis is never read or written.
import { describe, it, expect } from "bun:test";
import { mkdtempSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

const HOME = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), "outward-send-"));
process.env.HOME = HOME;
delete process.env.AEGIS_APPROVER_CONSUME_SOCKET;
delete process.env.AEGIS_APPROVER_APPROVE_SOCKET;
delete process.env.AEGIS_ALLOW_INSECURE_LOCAL_APPROVAL;

const K = await import("../src/kavach/outward");
const { sendPlugin, onList } = await import("../src/kavach/outward-send");
type SendProposal = import("../src/kavach/outward-send").SendProposal;
type Entry = import("../src/kavach/outward").OutwardLedgerEntry;

const NOW = new Date("2026-10-16T10:00:00Z");
const limits = (over: Record<string, unknown> = {}) => ({
  identities: ["desk-mari8x"], recipients: ["ops@known-shipping.example", "@partner.example"],
  ask_on_new_recipient: false, ask_always: false, per_lane_per_day: 10, lanes: ["mari8x"], ...over,
});
const mandate = (over: Record<string, unknown> = {}, extra: Record<string, unknown> = {}) => ({
  id: "send-1", kind: "send", limits: limits(over), reason: "test", granted_by: "human",
  granted_at: NOW.toISOString(), expires_at: new Date(NOW.getTime() + 86_400_000).toISOString(), ...extra,
});
const mail = (over: Partial<SendProposal> = {}): SendProposal => ({
  channel: "email", lane: "mari8x", from: "desk-mari8x", to: ["ops@known-shipping.example"],
  subject: "Voyage P&L check", body: "Hello, the summary you asked for is attached.", ...over,
});
const ctx = (over: Record<string, unknown> = {}) => ({
  session_id: "s1", now: NOW, mandates: [mandate()], ledger: [] as Entry[], flowStatus: "valid", ...over,
}) as any;
const enforced = { ...sendPlugin, stage: "enforce" as const };
const judge = (p: SendProposal, c = ctx()) => K.judgeOutward(enforced, p, c);
const ids = (d: any) => d.refusals.map((r: any) => r.id);

describe("ANU-012 — no live mandate, no outward act", () => {
  it("a live mandate naming the identity: PERMIT", () => {
    expect(judge(mail()).verdict).toBe("PERMIT");
  });
  it("no mandate, an expired one, a malformed one, or one for another identity: REFUSE", () => {
    expect(ids(judge(mail(), ctx({ mandates: [] })))).toContain("ANU-012");
    expect(ids(judge(mail(), ctx({ mandates: [mandate({}, { expires_at: NOW.toISOString() })] })))).toContain("ANU-012");
    expect(ids(judge(mail(), ctx({ mandates: [mandate({ recipients: "everyone" })] })))).toContain("ANU-012");
    expect(ids(judge(mail({ from: "captain" })))).toContain("ANU-012");
  });
  it("the session's flow mandate must be valid", () => {
    expect(judge(mail(), ctx({ flowStatus: "revoked" })).verdict).toBe("REFUSE");
  });
  it("ANU-012 enforces even when the plug-in is observe-staged", () => {
    const d = K.judgeOutward(sendPlugin, mail(), ctx({ mandates: [] }));
    expect(d.stage).toBe("observe");
    expect(d.verdict).toBe("REFUSE");
  });
});

describe("ANU-I-012 — send", () => {
  it("identity named: PERMIT; recipients exact or @domain", () => {
    expect(judge(mail({ to: ["a@partner.example", "ops@known-shipping.example"] })).verdict).toBe("PERMIT");
    expect(onList("A@Partner.Example", ["@partner.example"])).toBe(true);
    expect(onList("a@evil-partner.example", ["@partner.example"])).toBe(false);
  });
  it("a stranger anywhere (to, cc or bcc) refuses by default", () => {
    expect(ids(judge(mail({ bcc: ["someone@stranger.example"] })))).toContain("ANU-I-012.recipients");
  });
  it("a stranger asks when the mandate says ask_on_new_recipient", () => {
    const d = judge(mail({ to: ["someone@stranger.example"] }), ctx({ mandates: [mandate({ ask_on_new_recipient: true })] }));
    expect([d.verdict, d.ask]).toEqual(["PERMIT", true]);
  });
  it("ask_always: every message waits for the person", () => {
    expect(judge(mail(), ctx({ mandates: [mandate({ ask_always: true })] })).ask).toBe(true);
    expect(judge(mail()).ask).toBe(false);
  });
  it("a lane the mandate does not name refuses", () => {
    expect(ids(judge(mail({ lane: "tms" })))).toContain("ANU-I-012.lane");
  });
  it("a line break in the subject refuses (header injection)", () => {
    expect(ids(judge(mail({ subject: "Hi\r\nBcc: all@list.example" })))).toContain("ANU-I-012.shape");
  });
  it("a malformed address or empty body refuses", () => {
    expect(judge(mail({ to: ["not-an-address"] })).verdict).toBe("REFUSE");
    expect(judge(mail({ body: "  " })).verdict).toBe("REFUSE");
  });
  it("an unknown channel is UNKNOWN, which refuses", () => {
    expect(judge(mail({ channel: "sms" as any })).verdict).toBe("REFUSE");
  });
});

describe("ANU-014 — declared claims carry a source", () => {
  it("each claim with a URL: PERMIT", () => {
    expect(judge(mail({ claims: [{ text: "cuts port-call time", source_url: "https://ankr.in/proof/1" }] })).verdict).toBe("PERMIT");
  });
  it("a claim with no source: REFUSE", () => {
    expect(ids(judge(mail({ claims: [{ text: "cuts port-call time by 30%" }] })))).toContain("ANU-014");
  });
});

describe("ANU-015 — budget counts done and approved-not-done", () => {
  const entry = (hash: string, event: Entry["event"], clean = true, minsAgo = 10): Entry => ({
    ts: new Date(NOW.getTime() - minsAgo * 60_000).toISOString(), event, kind: "send", session: "s1",
    proposal_hash: hash, mandate_id: "send-1", budget_key: "lane:mari8x", units: 1, clean,
  });
  it("under the cap: PERMIT", () => {
    expect(judge(mail(), ctx({ ledger: [entry("a", "executed"), entry("b", "decided")] })).verdict).toBe("PERMIT");
  });
  it("at the cap (executed + approved-not-done + clean decisions): REFUSE", () => {
    const ledger = [entry("a", "executed"), entry("a", "decided"), entry("b", "approved"), entry("c", "decided")];
    const d = judge(mail(), ctx({ mandates: [mandate({ per_lane_per_day: 3 })], ledger }));
    expect(ids(d)).toContain("ANU-015");
  });
  it("refused decisions, other lanes and yesterday do not count", () => {
    const ledger = [entry("a", "decided", false), { ...entry("b", "executed"), budget_key: "lane:tms" }, entry("c", "executed", true, 25 * 60)];
    expect(judge(mail(), ctx({ mandates: [mandate({ per_lane_per_day: 1 })], ledger })).verdict).toBe("PERMIT");
  });
});

describe("ANU-YK-002 — a new plug-in ships observe", () => {
  it("the send plug-in's own rules report but do not refuse until promoted", () => {
    const d = K.judgeOutward(sendPlugin, mail({ to: ["someone@stranger.example"] }), ctx());
    expect(d.verdict).toBe("PERMIT");
    expect(d.observations.map((r: any) => r.id)).toContain("ANU-I-012.recipients");
  });
  it("promoted, the same proposal refuses", () => {
    expect(judge(mail({ to: ["someone@stranger.example"] })).verdict).toBe("REFUSE");
  });
});

describe("ANU-011 kernel discipline", () => {
  it("a permissive that throws is UNKNOWN and refuses", () => {
    const broken = { ...enforced, permissives: [{ id: "X", title: "x", law: "x", check: () => { throw new Error("boom"); } }] };
    expect(K.judgeOutward(broken as any, mail(), ctx()).refusals[0].verdict).toBe("UNKNOWN");
  });
  it("the proposal hash does not depend on key order", () => {
    const a = mail(); const b = JSON.parse(JSON.stringify({ body: a.body, to: a.to, subject: a.subject, from: a.from, lane: a.lane, channel: a.channel }));
    expect(K.proposalHash("send", a)).toBe(K.proposalHash("send", b));
  });
});

// ── execute: ANU-013 ask, ANU-016 hand-off, ANU-017 ledger ─────────────────────

const fakeMailer = () => {
  const sent: any[] = [];
  return { sent, effector: { name: "fake-mailer", deliver: async (h: any) => { sent.push(h); return { ref: `M${sent.length}` }; } } };
};
const fakeApprovals = (approved: Set<string>) => ({
  pending: [] as string[],
  async record(shown: string) { this.pending.push(shown); return `code${this.pending.length}`; },
  async consume(shown: string) { return approved.delete(shown); },
});

describe("executeOutward", () => {
  it("PERMIT without ask: handed to the effector, ledgered", async () => {
    const m = fakeMailer(); const log: Entry[] = [];
    const d = judge(mail());
    const r = await K.executeOutward(enforced, mail(), d, m.effector, fakeApprovals(new Set()), { fresh: () => ctx(), ledger: (e) => log.push(e) });
    expect(r).toEqual({ done: true, ref: "M1" });
    expect(Object.keys(m.sent[0]).sort()).toEqual(["bcc", "body", "cc", "from", "subject", "to"]);
    expect(log.map((e) => e.event)).toEqual(["executed"]);
  });
  it("REFUSE never reaches the effector", async () => {
    const m = fakeMailer();
    const d = judge(mail({ to: ["x@stranger.example"] }));
    const r = await K.executeOutward(enforced, mail({ to: ["x@stranger.example"] }), d, m.effector, fakeApprovals(new Set()), { fresh: () => ctx({ mandates: [mandate({ ask_always: true })] }), ledger: () => {} });
    expect(r.done).toBe(false);
    expect(m.sent.length).toBe(0);
  });
  it("ask: waits, returns a code; once the person approves this exact text, it goes once", async () => {
    const m = fakeMailer(); const approved = new Set<string>(); const ap = fakeApprovals(approved);
    const c = ctx({ mandates: [mandate({ ask_always: true })] });
    const d = judge(mail(), c);
    const fresh = () => c;
    const first = await K.executeOutward(enforced, mail(), d, m.effector, ap, { fresh, ledger: () => {} });
    expect(first).toMatchObject({ done: false, approval_code: "code1" });
    approved.add(d.shown);
    expect((await K.executeOutward(enforced, mail(), d, m.effector, ap, { fresh, ledger: () => {} })).done).toBe(true);
    expect((await K.executeOutward(enforced, mail(), d, m.effector, ap, { fresh, ledger: () => {} })).done).toBe(false); // consumed once
    expect(m.sent.length).toBe(1);
  });
  it("a proposal changed after judging is refused", async () => {
    const m = fakeMailer();
    const d = judge(mail());
    const r = await K.executeOutward(enforced, mail({ to: ["ops@known-shipping.example", "a@partner.example"] }), d, m.effector, fakeApprovals(new Set()), { fresh: () => ctx({ mandates: [mandate({ ask_always: true })] }), ledger: () => {} });
    expect(r.done).toBe(false);
    expect(m.sent.length).toBe(0);
  });
  it("an approval authority that throws refuses", async () => {
    const m = fakeMailer();
    const d = judge(mail(), ctx({ mandates: [mandate({ ask_always: true })] }));
    const r = await K.executeOutward(enforced, mail(), d, m.effector, { record: async () => "c", consume: async () => { throw new Error("down"); } }, { fresh: () => ctx({ mandates: [mandate({ ask_always: true })] }), ledger: () => {} });
    expect(r.done).toBe(false);
  });
});

describe("ANU-013 through aegis's own approval authority (scratch HOME)", () => {
  it("mode none: an ask can never be lifted", async () => {
    const m = fakeMailer(); const ap = await K.aegisApprovals();
    const d = judge(mail(), ctx({ mandates: [mandate({ ask_always: true })] }));
    const r = await K.executeOutward(enforced, mail(), d, m.effector, ap, { fresh: () => ctx({ mandates: [mandate({ ask_always: true })] }), ledger: () => {} });
    expect(r.done).toBe(false);
    expect(m.sent.length).toBe(0);
  });
  it("insecure-local: the person approves the code, the act goes once", async () => {
    process.env.AEGIS_ALLOW_INSECURE_LOCAL_APPROVAL = "1";
    try {
      const auth = await import("../src/kavach/approval-authority");
      const m = fakeMailer(); const ap = await K.aegisApprovals();
      const d = judge(mail({ subject: "approve me" }), ctx({ mandates: [mandate({ ask_always: true })] }));
      const first = await K.executeOutward(enforced, mail({ subject: "approve me" }), d, m.effector, ap, { fresh: () => ctx({ mandates: [mandate({ ask_always: true })] }), ledger: () => {} });
      expect(first.done).toBe(false);
      const code = (first as any).approval_code;
      const ok = await auth.approvePendingAuthority(code);
      expect(ok?.rule).toBe("ANU-013");
      expect((await K.executeOutward(enforced, mail({ subject: "approve me" }), d, m.effector, ap, { fresh: () => ctx({ mandates: [mandate({ ask_always: true })] }), ledger: () => {} })).done).toBe(true);
      expect(m.sent.length).toBe(1);
    } finally {
      delete process.env.AEGIS_ALLOW_INSECURE_LOCAL_APPROVAL;
    }
  });
});

it("the box's own ~/.aegis is not the one in use", () => {
  expect(K.OUTWARD_LEDGER.startsWith(HOME)).toBe(true);
});
