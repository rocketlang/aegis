// SPDX-License-Identifier: AGPL-3.0-only
// Text an agent chose, shown to a person or signed into a row (2.17.2).
import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { mkdtempSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { ledgerField, visible } from "../src/core/ledger-sign";
import { approvePending, consumeApproval, hashCommand, listPending, recordPending } from "../src/kavach/destructive-approval";

const ESC = String.fromCharCode(27);
describe("unseen characters", () => {
  it("UC-1: visible() writes out what a terminal would act on, and leaves the rest", () => {
    expect(visible(`a${ESC}[2Kb`)).toBe("a\\x1b[2Kb");
    expect(visible("a\rb\u0008c")).toBe("a\\x0db\\x08c");
    expect(visible("x‮y​z")).toBe("x\\u202ey\\u200bz");
    expect(visible("naïve — ₹ 日本 ok")).toBe("naïve — ₹ 日本 ok");
  });
  it("UC-2: ledgerField() clips, then replaces each unseen character by one '?'", () => {
    expect(ledgerField(`aegis-shield${ESC}[2K\rok`, 80)).toBe("aegis-shield?[2K?ok");
    expect(ledgerField("KAV-001", 60)).toBe("KAV-001");
    expect(ledgerField("x".repeat(100), 80)).toBe("x".repeat(80));
    expect(ledgerField("", 80)).toBeNull();
    expect(ledgerField(7, 80)).toBeNull();
  });
});

describe("an approval is for the command in its folder", () => {
  let dir = "", before: string | undefined;
  beforeEach(() => { before = process.env.AEGIS_DIR; dir = mkdtempSync(join(tmpdir(), "aegis-cwd-")); process.env.AEGIS_DIR = dir; });
  afterEach(() => { if (before === undefined) delete process.env.AEGIS_DIR; else process.env.AEGIS_DIR = before; rmSync(dir, { recursive: true, force: true }); });
  const cmd = ["rm", "-rf", "./build"].join(" ");
  it("CW-1: the hash covers the folder when there is one, and is the old hash when there is none", () => {
    expect(hashCommand(cmd, "/a")).not.toBe(hashCommand(cmd, "/b"));
    expect(hashCommand(cmd, "/a")).not.toBe(hashCommand(cmd));
    expect(hashCommand(cmd, null)).toBe(hashCommand(cmd));
    expect(hashCommand(cmd, "")).toBe(hashCommand(cmd));
    // the folder cannot be moved into the command text
    expect(hashCommand("x", "y")).not.toBe(hashCommand(JSON.stringify(["x", "y"])));
    expect(hashCommand("a", "bc")).not.toBe(hashCommand("ab", "c"));
    expect(hashCommand(cmd, "/a")).toMatch(/^[0-9a-f]{64}$/);
  });
  it("CW-2: approved in one folder, refused in another and with no folder, used once in the same", () => {
    const code = recordPending(cmd, "r", Date.now(), "/srv/project");
    expect(listPending()[0].cwd).toBe("/srv/project");
    expect(approvePending(code)?.cwd).toBe("/srv/project");
    expect(consumeApproval(cmd, Date.now(), "/srv/other")).toBe(false);
    expect(consumeApproval(cmd)).toBe(false);
    expect(consumeApproval(cmd, Date.now(), "/srv/project")).toBe(true);
    expect(consumeApproval(cmd, Date.now(), "/srv/project")).toBe(false);
  });
  it("CW-3: with no folder it is as before", () => {
    const code = recordPending(cmd, "r");
    expect(listPending()[0].cwd).toBeUndefined();
    expect(approvePending(code)).not.toBeNull();
    expect(consumeApproval(cmd)).toBe(true);
  });
  it("CW-4: what is stored for showing carries no character a terminal acts on", () => {
    recordPending(`echo hi #${ESC}[1A${ESC}[2K`, `r${ESC}[0m`, Date.now(), `/tmp/x${ESC}[8m`);
    const p = listPending()[0];
    for (const s of [p.shown, p.rule, p.cwd as string]) { expect(s.includes(ESC)).toBe(false); expect(s).toContain("\\x1b"); }
    expect(p.cut).toBe(false);
  });
});
