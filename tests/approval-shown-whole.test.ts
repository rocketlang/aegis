// SPDX-License-Identifier: AGPL-3.0-only
// The one-time approval covers what the person was shown (2.17.1).
//   AS-1  a command longer than SHOWN_MAX is marked cut and is not approved without `unseen`
//   AS-2  a command with a secret taken out is marked cut
//   AS-3  two waiting commands under one code: neither is approved
//   AS-4  a code held by another waiting command is lengthened for the new one
//   AS-5  rows written before 2.17.1 (no chars, no cut) are approved as before
// A throwaway AEGIS_DIR; nothing is run. Statements are assembled from words.
import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { approvePending, consumeApproval, hashCommand, listPending, recordPending, ApprovalRefused, SHOWN_MAX } from "../src/kavach/destructive-approval";

const W = (...w: string[]) => w.join(" ");
const TAIL = W("rm", "-rf", "/srv/data");
let dir = "", before: string | undefined;
beforeEach(() => { before = process.env.AEGIS_DIR; dir = mkdtempSync(join(tmpdir(), "aegis-shown-")); process.env.AEGIS_DIR = dir; });
afterEach(() => { if (before === undefined) delete process.env.AEGIS_DIR; else process.env.AEGIS_DIR = before; rmSync(dir, { recursive: true, force: true }); });

describe("an approval covers what the person was shown", () => {
  it("AS-1: a command longer than what is shown is not approved unseen", () => {
    const cmd = `echo ${"x".repeat(SHOWN_MAX)}; ${TAIL}`;
    const code = recordPending(cmd, "r");
    const p = listPending()[0];
    expect(p.cut).toBe(true);
    expect(p.chars).toBe(cmd.length);
    expect(p.shown.includes(TAIL)).toBe(false);
    expect(() => approvePending(code)).toThrow(ApprovalRefused);
    expect(consumeApproval(cmd)).toBe(false);
    expect(listPending().length).toBe(1);                       // still waiting: a refusal uses nothing up
    expect(approvePending(code, Date.now(), { unseen: true })?.hash).toBe(hashCommand(cmd));
    expect(consumeApproval(cmd)).toBe(true);
  });
  it("AS-1b: a command shown whole is not cut, up to the limit exactly", () => {
    const cmd = `echo ${"x".repeat(SHOWN_MAX - 5)}`;
    expect(cmd.length).toBe(SHOWN_MAX);
    const code = recordPending(cmd, "r");
    expect(listPending()[0].cut).toBe(false);
    expect(approvePending(code)).not.toBeNull();
  });
  it("AS-2: a command with a secret taken out is marked cut", () => {
    const cmd = `curl -H "Authorization: Bearer sk-ant-api03-${"A".repeat(40)}" https://example.invalid; ${TAIL}`;
    const code = recordPending(cmd, "r");
    const p = listPending()[0];
    if (p.shown !== cmd.replace(/\s+/g, " ")) {                 // the redactor changed it
      expect(p.cut).toBe(true);
      expect(() => approvePending(code)).toThrow(ApprovalRefused);
    } else expect(p.cut).toBe(false);
  });
  it("AS-3: two waiting commands under one code: neither is approved", () => {
    const a = "echo one", b = `${TAIL} # two`, code = hashCommand(a).slice(0, 8), now = Date.now();
    writeFileSync(join(dir, "destructive-pending.json"), JSON.stringify([
      { code, hash: hashCommand(b), shown: b, rule: "r", at: now - 1000 },
      { code, hash: hashCommand(a), shown: a, rule: "r", at: now },
    ]));
    expect(() => approvePending(code)).toThrow(/different refused commands/);
    expect(consumeApproval(a)).toBe(false);
    expect(consumeApproval(b)).toBe(false);
    expect(listPending().length).toBe(2);
  });
  it("AS-4: a code held by another waiting command is lengthened for the new one", () => {
    const x = "echo three", other = `${TAIL} # four`;
    writeFileSync(join(dir, "destructive-pending.json"), JSON.stringify([{ code: hashCommand(x).slice(0, 8), hash: hashCommand(other), shown: other, rule: "r", at: Date.now() }]));
    const code = recordPending(x, "r");
    expect(code).toBe(hashCommand(x).slice(0, 12));
    expect(approvePending(code)?.hash).toBe(hashCommand(x));
    expect(consumeApproval(other)).toBe(false);
    expect(consumeApproval(x)).toBe(true);
    // the same command refused twice keeps one row and its first code
    expect(recordPending("echo five", "r")).toBe(recordPending("echo five", "r"));
  });
  it("AS-5: a row written before 2.17.1 is approved as before", () => {
    const a = "echo six";
    writeFileSync(join(dir, "destructive-pending.json"), JSON.stringify([{ code: hashCommand(a).slice(0, 8), hash: hashCommand(a), shown: a, rule: "r", at: Date.now() }]));
    expect(approvePending(hashCommand(a).slice(0, 8))).not.toBeNull();
    expect(approvePending("zzzzzzzz")).toBeNull();
    expect(approvePending("abc")).toBeNull();
  });
});
