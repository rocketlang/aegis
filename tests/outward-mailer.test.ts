// SPDX-License-Identifier: AGPL-3.0-only
// The send guard connected to ankr-mailer (founder, 2026-10-16): the mailer effector, and
// `aegis outward-send` end to end against a FAKE mailer (a local HTTP server in this process).
// Scratch HOME and AEGIS_HOME; no real mail can leave: AEGIS_MAILER_URL points at the fake.
import { describe, it, expect, beforeAll, afterAll } from "bun:test";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

const ROOT = join(import.meta.dir, "..");
const BASE = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), "outward-mailer-"));
process.env.HOME = BASE;
const { mailerEffector, mailerUrl } = await import("../src/kavach/outward-mailer");

type Got = { to: unknown; subject: string; text: string; account: string; noSignature: boolean };
const got: Got[] = [];
let answer: { status: number; body: unknown } = { status: 200, body: null };
let server: ReturnType<typeof Bun.serve>;
let URL_ = "";
beforeAll(() => {
  server = Bun.serve({
    port: 0,
    async fetch(req) {
      if (new URL(req.url).pathname !== "/send") return new Response("no", { status: 404 });
      const b = (await req.json()) as Got & { attachments?: { filename: string; path: string; seen?: string }[] };
      // The guard removes its copies after the send: read them now, as the real mailer would.
      for (const a of b.attachments ?? []) a.seen = readFileSync(a.path, "utf8");
      got.push(b);
      const body = answer.body ?? { ok: true, messageId: `<fake-${got.length}@test>`, to: b.to };
      return Response.json(body, { status: answer.status });
    },
  });
  URL_ = `http://127.0.0.1:${server.port}`;
});
afterAll(() => server.stop(true));

const AEGIS = join(BASE, ".aegis");
const MANDATES = join(AEGIS, "outward-mandates.json");
const LEDGER = join(AEGIS, "outward.jsonl");
const grant = (limits: Record<string, unknown>, extra: Record<string, unknown> = {}) => {
  mkdirSync(AEGIS, { recursive: true });
  const now = Date.now();
  writeFileSync(MANDATES, JSON.stringify([{
    id: "send-t", kind: "send", reason: "test", granted_by: "tester", granted_at: new Date(now).toISOString(),
    expires_at: new Date(now + 3600e3).toISOString(),
    limits: { identities: ["desk-mari8x"], recipients: ["ops@known.example"], per_lane_per_day: 10, lanes: ["mari8x"], ...limits }, ...extra,
  }]));
};
const reset = () => { got.length = 0; answer = { status: 200, body: null }; rmSync(LEDGER, { force: true }); rmSync(MANDATES, { force: true }); };
const mail = (over: Record<string, unknown> = {}) => ({
  channel: "email", lane: "mari8x", from: "desk-mari8x", to: ["ops@known.example"], subject: "Voyage P&L", body: "The summary.", why: "They asked for it.",
  claims: [{ text: "cuts reconciliation time", source_url: "https://ankr.in/proof/1" }], ...over,
});
async function send(p: unknown, flags: string[] = [], env: Record<string, string | undefined> = {}) {
  const e: Record<string, string> = {};
  for (const [k, v] of Object.entries({ ...process.env, HOME: BASE, AEGIS_HOME: AEGIS, AEGIS_MAILER_URL: URL_, AEGIS_REFUSAL_LEDGER: join(BASE, "refusals.jsonl"), CLAUDE_CODE_SESSION_ID: undefined, AEGIS_APPROVER_CONSUME_SOCKET: undefined, AEGIS_ALLOW_INSECURE_LOCAL_APPROVAL: undefined, ...env })) if (v !== undefined) e[k] = v;
  const proc = Bun.spawn(["bun", "run", join(ROOT, "src/cli/index.ts"), "outward-send", "--proposal", JSON.stringify(p), "--json", ...flags], { env: e, stdout: "pipe", stderr: "pipe" });
  const [out, err, code] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited]);
  let j: any = null; try { j = JSON.parse(out.trim().split("\n").pop() ?? ""); } catch { /* none */ }
  return { code, j, err };
}
const ledger = () => (existsSync(LEDGER) ? readFileSync(LEDGER, "utf8").trim().split("\n").map((l) => JSON.parse(l)) : []);

describe("mailer effector", () => {
  it("posts only the message, as the mailer expects, and returns its message id", async () => {
    reset();
    const r = await mailerEffector(URL_).deliver({ from: "desk-mari8x", to: ["a@x.example"], cc: [], bcc: [], subject: "s", body: "b" });
    expect(r.ref).toBe("<fake-1@test>");
    expect(got[0]).toEqual({ to: "a@x.example", subject: "s", text: "b", account: "desk-mari8x", noSignature: true });
  });
  it("cc or bcc: refused, nothing posted (the mailer would drop them)", async () => {
    reset();
    await expect(mailerEffector(URL_).deliver({ from: "d", to: ["a@x.example"], cc: ["c@x.example"], bcc: [], subject: "s", body: "b" })).rejects.toThrow("cannot carry cc or bcc");
    expect(got.length).toBe(0);
  });
  it("a mailer refusal (403 word list) or a 200 without ok is a failure, not a send", async () => {
    reset();
    answer = { status: 403, body: { error: "demo-guard" } };
    await expect(mailerEffector(URL_).deliver({ from: "d", to: ["a@x.example"], cc: [], bcc: [], subject: "s", body: "b" })).rejects.toThrow("403");
    answer = { status: 200, body: { nothing: true } };
    await expect(mailerEffector(URL_).deliver({ from: "d", to: ["a@x.example"], cc: [], bcc: [], subject: "s", body: "b" })).rejects.toThrow();
  });
  it("the mailer's address comes from ports.json backend.ankrMailer, and no port means no send", () => {
    const saved = process.env.AEGIS_MAILER_URL; delete process.env.AEGIS_MAILER_URL;
    try {
      const p = join(BASE, "ports.json");
      writeFileSync(p, JSON.stringify({ backend: { ankrMailer: 4061 } }));
      expect(mailerUrl(p)).toBe("http://127.0.0.1:4061");
      writeFileSync(p, JSON.stringify({ backend: {} }));
      expect(() => mailerUrl(p)).toThrow("R-008");
    } finally { if (saved) process.env.AEGIS_MAILER_URL = saved; }
  });
});

describe("aegis outward-send, end to end against the fake mailer", () => {
  it("no send mandate: refused (exit 2), nothing reaches the mailer", async () => {
    reset();
    const r = await send(mail());
    expect([r.code, r.j?.sent, got.length]).toEqual([2, false, 0]);
    expect(r.j.refusals.join()).toContain("ANU-012");
  });
  it("a mandate for this identity and a listed recipient: sent once (exit 0), ledgered decided + executed", async () => {
    reset(); grant({});
    const r = await send(mail());
    expect([r.code, r.j?.sent, r.j?.ref]).toEqual([0, true, "<fake-1@test>"]);
    expect(got.length).toBe(1);
    expect(ledger().map((e) => e.event)).toEqual(["decided", "executed"]);
  });
  it("an identity the mandate does not name: refused", async () => {
    reset(); grant({});
    const r = await send(mail({ from: "captain" }));
    expect([r.code, got.length]).toEqual([2, 0]);
  });
  it("cc on a proposal: not sent (the mailer cannot carry it), exit 1", async () => {
    reset(); grant({ recipients: ["ops@known.example", "cc@known.example"] });
    const r = await send(mail({ cc: ["cc@known.example"] }));
    expect([r.code, r.j?.sent, got.length]).toEqual([1, false, 0]);
  });
  it("a new recipient under ask_on_new_recipient: waits with a code (exit 2), nothing sent", async () => {
    reset(); grant({ ask_on_new_recipient: true });
    const r = await send(mail({ to: ["someone@stranger.example"] }));
    expect([r.code, r.j?.ask, r.j?.sent, got.length]).toEqual([2, true, false, 0]);
    expect(r.j.next ?? r.j.reason).toBeTruthy();
  });
  it("ENFORCED (founder, 2026-10-16): a stranger with no ask rule is refused, nothing sent, the refusal ledgered", async () => {
    reset(); grant({});
    const r = await send(mail({ to: ["someone@stranger.example"] }));
    expect([r.code, r.j?.sent, r.j?.stage, got.length]).toEqual([2, false, "enforce", 0]);
    expect(r.j.refusals.join()).toContain("ANU-I-012.recipients");
    expect(ledger()[0].results.some((x: any) => x.id === "ANU-I-012.recipients" && x.verdict === "REFUSE")).toBe(true);
  });
  it("ENFORCED: over the lane's daily cap is refused; a claim with no proof is refused", async () => {
    reset(); grant({ per_lane_per_day: 1 });
    expect((await send(mail())).code).toBe(0);
    const second = await send(mail({ subject: "another" }));
    expect([second.code, got.length]).toEqual([2, 1]);
    expect(second.j.refusals.join()).toContain("ANU-015");
    reset(); grant({});
    const bare = await send(mail({ claims: [{ text: "cuts time by 30%" }] }));
    expect([bare.code, got.length]).toEqual([2, 0]);
    expect(bare.j.refusals.join()).toContain("ANU-014");
  });
  it("two mandates for one identity: the one whose lane fits is used, not the first in the file", async () => {
    reset();
    mkdirSync(AEGIS, { recursive: true });
    const now = Date.now();
    const m = (id: string, lanes: string[]) => ({
      id, kind: "send", reason: "test", granted_by: "tester", granted_at: new Date(now).toISOString(),
      expires_at: new Date(now + 3600e3).toISOString(),
      limits: { identities: ["captain"], recipients: ["ops@known.example"], per_lane_per_day: 10, lanes },
    });
    writeFileSync(MANDATES, JSON.stringify([m("send-review", ["review"]), m("send-mari8x", ["mari8x"])]));
    const r = await send(mail({ from: "captain" }), ["--dry-run"]);
    expect([r.code, r.j?.verdict, r.j?.mandate_id]).toEqual([0, "PERMIT", "send-mari8x"]);
    const other = await send(mail({ from: "captain", lane: "tms" }), ["--dry-run"]);
    expect([other.code, other.j?.mandate_id]).toEqual([2, "send-review"]);
    expect(other.j.refusals.join()).toContain("ANU-I-012.lane");
  });
  it("two mandates for one identity AND lane: the one whose list holds the recipients is used (23 Oct: a test mandate shadowed a batch)", async () => {
    reset();
    mkdirSync(AEGIS, { recursive: true });
    const now = Date.now();
    const m = (id: string, recipients: string[], extra: Record<string, unknown> = {}) => ({
      id, kind: "send", reason: "test", granted_by: "tester", granted_at: new Date(now).toISOString(),
      expires_at: new Date(now + 3600e3).toISOString(),
      limits: { identities: ["xshield-go"], recipients, per_lane_per_day: 10, lanes: ["xshield"], ...extra },
    });
    const base = { from: "xshield-go", lane: "xshield", claims: [] };
    writeFileSync(MANDATES, JSON.stringify([m("send-test", ["founder@own.example"]), m("send-batch", ["info@agency.example", "@other.example"])]));
    const batch = await send(mail({ ...base, to: ["info@agency.example"] }), ["--dry-run"]);
    expect([batch.code, batch.j?.verdict, batch.j?.mandate_id]).toEqual([0, "PERMIT", "send-batch"]);
    const byDomain = await send(mail({ ...base, to: ["hello@other.example"] }), ["--dry-run"]);
    expect([byDomain.code, byDomain.j?.mandate_id]).toEqual([0, "send-batch"]);
    const founder = await send(mail({ ...base, to: ["founder@own.example"] }), ["--dry-run"]);
    expect([founder.code, founder.j?.mandate_id]).toEqual([0, "send-test"]);
    // Recipients split across two mandates: no single grant covers the message, so it is refused, not stitched together.
    const split = await send(mail({ ...base, to: ["founder@own.example", "info@agency.example"] }), ["--dry-run"]);
    expect(split.code).toBe(2);
    expect(split.j.refusals.join()).toContain("ANU-I-012.recipients");
    const stranger = await send(mail({ ...base, to: ["x@nowhere.example"] }), ["--dry-run"]);
    expect([stranger.code, stranger.j?.mandate_id]).toEqual([2, "send-test"]);
    // Nobody lists the address, but one mandate asks the person about new recipients: that one is used (ask, not refuse).
    writeFileSync(MANDATES, JSON.stringify([m("send-test", ["founder@own.example"]), m("send-ask", ["a@b.example"], { ask_on_new_recipient: true })]));
    const asked = await send(mail({ ...base, to: ["x@nowhere.example"] }), ["--dry-run"]);
    expect([asked.j?.mandate_id, asked.j?.ask]).toEqual(["send-ask", true]);
  });
  it("--dry-run judges only: nothing sent, nothing ledgered", async () => {
    reset(); grant({});
    const r = await send(mail(), ["--dry-run"]);
    expect([r.code, r.j?.dry_run, got.length, existsSync(LEDGER)]).toEqual([0, true, 0, false]);
  });
  it("an agent session with no valid flow mandate: refused (ANU-012)", async () => {
    reset(); grant({});
    const r = await send(mail(), [], { CLAUDE_CODE_SESSION_ID: "no-such-session-for-this-test" });
    expect([r.code, got.length]).toEqual([2, 0]);
    expect(r.j.refusals.join()).toContain("agent session");
  });
  it("the mailer refusing (word list): exit 1, not counted as sent", async () => {
    reset(); grant({});
    answer = { status: 403, body: { error: "demo-guard" } };
    const r = await send(mail());
    expect([r.code, r.j?.sent]).toEqual([1, false]);
    expect(ledger().map((e) => e.event)).toEqual(["decided", "execute-refused"]);
  });
  describe("attachments", () => {
    const OUT = join(BASE, "outbox"), ELSE = join(BASE, "elsewhere");
    mkdirSync(OUT, { recursive: true }); mkdirSync(ELSE, { recursive: true });
    const file = (dir: string, name: string, text: string) => { const p = join(dir, name); writeFileSync(p, text); return p; };
    const sha = (s: string) => new Bun.CryptoHasher("sha256").update(s).digest("hex");
    const one = file(OUT, "prereg.json", '{"a":1}');

    it("a mandate with attach_from and a file inside it, hash matching: sent, the mailer gets a copy with the same bytes", async () => {
      reset(); grant({ attach_from: [OUT] });
      const r = await send(mail({ attachments: [{ path: one, sha256: sha('{"a":1}') }] }));
      expect([r.code, r.j?.sent]).toEqual([0, true]);
      const a = (got[0] as any).attachments;
      expect(a.length).toBe(1);
      expect([a[0].filename, a[0].seen]).toEqual(["prereg.json", '{"a":1}']);
      expect(a[0].path).not.toBe(one);            // the checked copy, not the original
      expect(existsSync(a[0].path)).toBe(false);  // and the copy is gone after the send
    });
    it("no attach_from in the mandate: refused, nothing sent", async () => {
      reset(); grant({});
      const r = await send(mail({ attachments: [{ path: one, sha256: sha('{"a":1}') }] }));
      expect([r.code, got.length]).toEqual([2, 0]);
      expect(r.j.refusals.join()).toContain("does not allow attachments");
    });
    it("a file outside attach_from, or reached through a symlink out of it: refused", async () => {
      reset(); grant({ attach_from: [OUT] });
      const out = file(ELSE, "key.txt", "secret");
      expect((await send(mail({ attachments: [{ path: out, sha256: sha("secret") }] }))).code).toBe(2);
      const link = join(OUT, "link.txt");
      rmSync(link, { force: true }); require("fs").symlinkSync(out, link);
      const r = await send(mail({ attachments: [{ path: link, sha256: sha("secret") }] }));
      expect([r.code, got.length]).toEqual([2, 0]);
      expect(r.j.refusals.join()).toContain("not inside a directory");
      const dots = await send(mail({ attachments: [{ path: join(OUT, "..", "elsewhere", "key.txt"), sha256: sha("secret") }] }));
      expect([dots.code, got.length]).toEqual([2, 0]);
    });
    it("a file whose SHA-256 is not the proposal's: refused, nothing sent", async () => {
      reset(); grant({ attach_from: [OUT] });
      const r = await send(mail({ attachments: [{ path: one, sha256: sha("something else") }] }));
      expect([r.code, got.length]).toEqual([2, 0]);
      expect(r.j.refusals.join()).toContain("file changed");
    });
    it("a relative path, a directory, or a bad hash: refused", async () => {
      reset(); grant({ attach_from: [OUT] });
      for (const a of [{ path: "outbox/prereg.json", sha256: sha('{"a":1}') }, { path: OUT, sha256: sha("") }, { path: one, sha256: "ABC" }]) {
        expect((await send(mail({ attachments: [a] }))).code).toBe(2);
      }
      expect(got.length).toBe(0);
    });
    it("the effector: a file changed after judging is not sent", async () => {
      reset();
      const p = file(OUT, "late.txt", "before");
      await expect(mailerEffector(URL_).deliver({ from: "d", to: ["a@x.example"], cc: [], bcc: [], subject: "s", body: "b", attachments: [{ path: p, sha256: sha("after") }] })).rejects.toThrow("changed after it was judged");
      expect(got.length).toBe(0);
    });
    it("a mandate whose attach_from is relative or the filesystem root is not valid", async () => {
      const { sendPlugin } = await import("../src/kavach/outward-send");
      const base = { identities: ["d"], recipients: ["a@x.example"], per_lane_per_day: 1 };
      expect(sendPlugin.parseLimits({ ...base, attach_from: ["outbox"] })).toBeNull();
      expect(sendPlugin.parseLimits({ ...base, attach_from: ["/"] })).toBeNull();
      expect(sendPlugin.parseLimits({ ...base, attach_from: [OUT] })?.attach_from).toEqual([OUT]);
      expect(sendPlugin.parseLimits(base)?.attach_from).toBeUndefined();
    });
  });

  it("a proposal that is not JSON: exit 3 (broke), nothing sent", async () => {
    reset();
    const proc = Bun.spawn(["bun", "run", join(ROOT, "src/cli/index.ts"), "outward-send", "--proposal", "{nope"], { env: { ...process.env, HOME: BASE, AEGIS_MAILER_URL: URL_ } as any, stdout: "pipe", stderr: "pipe" });
    expect(await proc.exited).toBe(3);
    expect(got.length).toBe(0);
  });
});
