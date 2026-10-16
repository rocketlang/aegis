// SPDX-License-Identifier: AGPL-3.0-only
// `aegis outward-mandate` (ANU-012) and the shield's KAV-101. Both outcomes per rule. The CLI runs
// as a child process under a scratch HOME and AEGIS_HOME, so the box's own ~/.aegis is never touched.
import { describe, it, expect } from "bun:test";
import { mkdtempSync, readFileSync, existsSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

const ROOT = join(import.meta.dir, "..");
const BASE = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), "outward-mandate-"));
process.env.HOME = BASE;
const K = await import("../src/kavach/outward");
const { sendPlugin } = await import("../src/kavach/outward-send");
const { bashFileVerdict, loadShieldRules } = await import("../src/shield/injection-detector");
const PS = await import("../src/kavach/plant-state");

const FILE = join(BASE, ".aegis", "outward-mandates.json");
const HIST = join(BASE, ".aegis", "outward-mandates.history.jsonl");
const cli = (...args: string[]) => {
  const r = Bun.spawnSync(["bun", "run", join(ROOT, "src/cli/index.ts"), "outward-mandate", ...args], {
    env: { ...process.env, HOME: BASE, AEGIS_HOME: join(BASE, ".aegis"), AEGIS_REFUSAL_LEDGER: join(BASE, "refusals.jsonl"), USER: "tester" },
  });
  return { code: r.exitCode, out: r.stdout.toString(), err: r.stderr.toString() };
};
const mandates = () => (existsSync(FILE) ? JSON.parse(readFileSync(FILE, "utf8")) : []);
const SEND = JSON.stringify({ identities: ["desk-mari8x"], recipients: ["ops@known.example", "@partner.example"], per_lane_per_day: 10, lanes: ["mari8x"] });

describe("grant", () => {
  it("valid send limits: granted, written, in the history, the limits printed whole, width noted", () => {
    const r = cli("grant", "send", "--id", "send-a", "--reason", "mari8x desk this week", "--limits", SEND, "--ttl-hours", "48");
    expect(r.code).toBe(0);
    expect(r.out).toContain("mandate granted");
    expect(r.out).toContain('"ops@known.example"');
    expect(r.out).toContain("NOTE: @partner.example permit ANYONE");
    const m = mandates().find((x: any) => x.id === "send-a");
    expect([m.kind, m.granted_by, m.reason]).toEqual(["send", "tester", "mari8x desk this week"]);
    expect(Date.parse(m.expires_at) - Date.parse(m.granted_at)).toBe(48 * 3600e3);
    expect(readFileSync(HIST, "utf8")).toContain('"act":"grant"');
  });
  it("the granted mandate is what the kernel reads: a listed mail is permitted", () => {
    const d = K.judgeOutward({ ...sendPlugin, stage: "enforce" }, {
      channel: "email", lane: "mari8x", from: "desk-mari8x", to: ["ops@known.example"], subject: "s", body: "b",
    }, { session_id: "s", now: new Date(), mandates: K.readOutwardMandates(FILE), ledger: [], flowStatus: "valid" });
    expect(d.verdict).toBe("PERMIT");
  });
  it("invalid limits, unknown kind, no reason, bad ttl, both limit sources: refused, nothing written", () => {
    const before = readFileSync(FILE, "utf8");
    expect(cli("grant", "send", "--reason", "x", "--limits", '{"identities":[]}').code).toBe(1);
    expect(cli("grant", "teleport", "--reason", "x", "--limits", SEND).code).toBe(1);
    expect(cli("grant", "send", "--limits", SEND).code).toBe(1);
    expect(cli("grant", "send", "--reason", "x", "--limits", SEND, "--ttl-hours", "0").code).toBe(1);
    expect(cli("grant", "send", "--reason", "x", "--limits", SEND, "--ttl-hours", "400").code).toBe(1);
    const f = join(BASE, "l.json"); writeFileSync(f, SEND);
    expect(cli("grant", "send", "--reason", "x", "--limits", SEND, "--limits-file", f).code).toBe(1);
    expect(cli("grant", "send", "--reason", "x", "--limits", "{not json").code).toBe(1);
    expect(readFileSync(FILE, "utf8")).toBe(before);
  });
  it("a live id cannot be granted twice", () => {
    expect(cli("grant", "send", "--id", "send-a", "--reason", "again", "--limits", SEND).code).toBe(1);
  });
  it("from a limits file: granted", () => {
    const f = join(BASE, "l2.json"); writeFileSync(f, SEND);
    expect(cli("grant", "send", "--id", "send-b", "--reason", "file", "--limits-file", f).code).toBe(0);
  });
  it("spend: the id is the limits' mandate_id; a different --id is refused", () => {
    const spend = { mandate_id: "m-books", agent_id: "cc:s1", currency: "INR", per_purchase_cap: 200000, period_cap: 1000000, period_days: 30, merchants: ["bookhaven"], categories: ["books"], ask_above: 100000, ask_on_new_merchant: false, freshness_seconds: 900 };
    expect(cli("grant", "spend", "--id", "other", "--reason", "x", "--limits", JSON.stringify(spend)).code).toBe(1);
    expect(cli("grant", "spend", "--reason", "books", "--limits", JSON.stringify(spend)).code).toBe(0);
    expect(mandates().some((m: any) => m.id === "m-books" && m.kind === "spend")).toBe(true);
    const wide = cli("grant", "spend", "--reason", "wide", "--limits", JSON.stringify({ ...spend, mandate_id: "m-wide", ask_above: 300000 }));
    expect(wide.out).toContain("no purchase will ever be asked about");
  });
});

describe("list, show, revoke", () => {
  it("list and show", () => {
    expect(cli("list").out).toContain("send-a  [send]");
    expect(cli("list", "spend").out).not.toContain("send-a");
    expect(cli("show", "send-a").out).toContain('"per_lane_per_day": 10');
    expect(cli("show", "nope").code).toBe(1);
  });
  it("revoke removes it, records why, and an act judged under it is refused at hand-off", () => {
    const plugin = { ...sendPlugin, stage: "enforce" as const };
    const mail = { channel: "email" as const, lane: "mari8x", from: "desk-mari8x", to: ["ops@known.example"], subject: "s", body: "b" };
    const fresh = () => ({ session_id: "s", now: new Date(), mandates: K.readOutwardMandates(FILE).filter((m) => m.id === "send-a"), ledger: [], flowStatus: "valid" });
    const judged = K.judgeOutward(plugin, mail, fresh());
    expect(judged.verdict).toBe("PERMIT");
    const r = cli("revoke", "send-a", "--reason", "desk closed");
    expect(r.code).toBe(0);
    expect(mandates().some((m: any) => m.id === "send-a")).toBe(false);
    expect(readFileSync(HIST, "utf8")).toContain('"reason":"desk closed"');
    expect(K.preflightOutward(plugin, mail, judged, fresh).ok).toBe(false);
    expect(cli("revoke", "send-a").code).toBe(1);
  });
  it("--help-limits prints the fields for each kind", () => {
    const r = cli("--help-limits");
    expect([r.code, r.out.includes("per_lane_per_day"), r.out.includes("freshness_seconds")]).toEqual([0, true, true]);
  });
});

describe("KAV-101 — granting is a person's act", () => {
  const rules = loadShieldRules();
  const sh = (c: string) => bashFileVerdict(c, rules, { cwd: "/root", home: "/root" });
  it("a grant arriving as a tool call is refused, however it is spelled", () => {
    for (const c of [
      `aegis outward-mandate grant send --reason x --limits '${SEND}'`,
      "bun run src/cli/index.ts outward-mandate grant spend --reason x --limits-file l.json",
      "cd /root/aegis && aegis outward-mandate grant send --reason x --limits-file /tmp/l.json",
      "npx @xshieldai/aegis outward-mandate grant send --reason x --limits '{}'",
    ]) expect([c, sh(c).rule_id]).toEqual([c, "KAV-101"]);
  });
  it("list, show, revoke and merely mentioning it are not refused", () => {
    for (const c of [
      "aegis outward-mandate list", "aegis outward-mandate show send-a", "aegis outward-mandate revoke send-a --reason done",
      "grep -rn 'outward-mandate grant' src", "echo run: aegis outward-mandate grant send", "aegis publish-mandate list",
    ]) expect([c, sh(c).rule_id]).not.toEqual([c, "KAV-101"]);
  });
});

it("the mandates file is a protected source (ANU-I-005 refuses hand edits)", () => {
  expect(PS.isProtectedSource(PS.OUTWARD_MANDATES_FILE)).toBe(true);
});
