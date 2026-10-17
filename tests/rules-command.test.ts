// SPDX-License-Identifier: AGPL-3.0-only
// aegis rules status | update — bringing an installed rules file up to the package's (KAV-102).
//
// What these pin:
//   §R1 plan     replaced patterns are dropped, missing ones added, the installer's own kept
//   §R2 the CLI  under a throwaway HOME: status exit codes, --dry writes nothing, update keeps a
//                backup, a link or an unreadable file is not replaced
//   §R3 shield   the update is a person's act; status is not refused
//
// Nothing here touches the real aegis home. Patterns are assembled from words.

import { describe, it, expect } from "bun:test";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, readdirSync, symlinkSync, existsSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { planRules, mergedRules } from "../src/cli/commands/rules";
import { bashFileVerdict, loadShieldRules } from "../src/shield/injection-detector";

const PKG_PATH = new URL("../rules/destructive-rules.json", import.meta.url).pathname;
const PKG = JSON.parse(readFileSync(PKG_PATH, "utf-8"));
const RETIRED: string[] = PKG._retired_patterns;
const OWN = { pattern: "terraform\\s+destroy", flags: "i", reason: "the installer's own rule", severity: "CRITICAL" };
const CLI = new URL("../src/cli/index.ts", import.meta.url).pathname;

/** An installed copy as an older version left it: two current patterns replaced by retired ones, plus one of the installer's. */
function olderInstall() {
  const pats = PKG.bash_block_patterns.slice(2).map((r: any) => ({ ...r }));
  return { _version: "1.1.0", bash_block_patterns: [{ ...PKG.bash_block_patterns[0], pattern: RETIRED[0] }, ...pats, OWN] };
}

function home(installed?: unknown): string {
  const h = mkdtempSync(join(tmpdir(), "aegis-rules-"));
  mkdirSync(join(h, ".aegis"));
  if (installed !== undefined) writeFileSync(join(h, ".aegis/destructive-rules.json"), typeof installed === "string" ? installed : JSON.stringify(installed));
  return h;
}
function run(h: string, ...args: string[]) {
  const p = Bun.spawnSync(["bun", CLI, "rules", ...args], { env: { ...process.env, HOME: h }, stdout: "pipe", stderr: "pipe" });
  return { code: p.exitCode, out: p.stdout.toString() + p.stderr.toString() };
}
const installed = (h: string) => JSON.parse(readFileSync(join(h, ".aegis/destructive-rules.json"), "utf-8"));

describe("§R1 the plan", () => {
  it("RU-101: a retired pattern is outdated, a current one missing, the installer's own kept", () => {
    const plan = planRules(olderInstall(), PKG);
    expect(plan.outdated.map((r) => r.pattern)).toEqual([RETIRED[0]]);
    expect(plan.missing.map((r) => r.pattern)).toEqual(PKG.bash_block_patterns.slice(0, 2).map((r: any) => r.pattern));
    expect(plan.local).toEqual([OWN]);
  });
  it("RU-102: the merged file is the package's patterns, then the installer's, and no retired one", () => {
    const m = mergedRules(olderInstall(), PKG);
    expect(m.bash_block_patterns.map((r) => r.pattern)).toEqual([...PKG.bash_block_patterns.map((r: any) => r.pattern), OWN.pattern]);
    for (const r of RETIRED) expect(m.bash_block_patterns.some((x) => x.pattern === r)).toBe(false);
    expect(m._version).toBe(PKG._version);
  });
  it("RU-103: every retired pattern is one the package no longer ships", () => {
    const now = new Set(PKG.bash_block_patterns.map((r: any) => r.pattern));
    for (const r of RETIRED) expect(now.has(r)).toBe(false);
  });
});

describe("§R2 the command, under a throwaway HOME", () => {
  it("RU-201: status says 1 for an older copy, 0 for a current one, 1 for none", () => {
    expect(run(home(olderInstall()), "status").code).toBe(1);
    expect(run(home(PKG), "status").code).toBe(0);
    expect(run(home(), "status").code).toBe(1);
  });
  it("RU-202: --dry writes nothing", () => {
    const h = home(olderInstall());
    const before = readFileSync(join(h, ".aegis/destructive-rules.json"), "utf-8");
    const r = run(h, "update", "--dry");
    expect(r.code).toBe(0);
    expect(readFileSync(join(h, ".aegis/destructive-rules.json"), "utf-8")).toBe(before);
    expect(readdirSync(join(h, ".aegis")).filter((f) => f.includes(".bak-"))).toEqual([]);
  });
  it("RU-203: update writes the merged file, keeps a backup of the old, and status is then 0", () => {
    const h = home(olderInstall());
    const r = run(h, "update");
    expect(r.code).toBe(0);
    expect(installed(h).bash_block_patterns.map((x: any) => x.pattern)).toEqual(mergedRules(olderInstall(), PKG).bash_block_patterns.map((x) => x.pattern));
    const baks = readdirSync(join(h, ".aegis")).filter((f) => f.includes(".bak-"));
    expect(baks.length).toBe(1);
    expect(JSON.parse(readFileSync(join(h, ".aegis", baks[0]), "utf-8"))).toEqual(olderInstall());
    expect(run(h, "status").code).toBe(0);
    expect(run(h, "update").out).toContain("already current");
  });
  it("RU-204: no installed file — update installs the package's", () => {
    const h = home();
    expect(run(h, "update").code).toBe(0);
    expect(installed(h).bash_block_patterns.length).toBe(PKG.bash_block_patterns.length);
  });
  it("RU-205: a file that does not read as rules, or a link, is not replaced", () => {
    const h = home("{ not json");
    expect(run(h, "update").code).toBe(1);
    expect(readFileSync(join(h, ".aegis/destructive-rules.json"), "utf-8")).toBe("{ not json");
    const h2 = home();
    const target = join(h2, "elsewhere.json");
    writeFileSync(target, JSON.stringify(olderInstall()));
    symlinkSync(target, join(h2, ".aegis/destructive-rules.json"));
    expect(run(h2, "update").code).toBe(1);
    expect(JSON.parse(readFileSync(target, "utf-8"))).toEqual(olderInstall());
    expect(existsSync(join(h2, ".aegis/destructive-rules.json.bak"))).toBe(false);
  });
});

describe("§R3 the update is a person's act (KAV-102)", () => {
  const rules = loadShieldRules();
  const ctx = { cwd: "/home/u/project", home: "/home/u" };
  const sh = (c: string) => bashFileVerdict(c, rules, ctx);
  const UPD = ["rules", "update"].join(" ");
  it("RU-301: refused as a tool call, however aegis is invoked", () => {
    for (const c of [`aegis ${UPD}`, `aegis ${UPD} --dry`, `sudo aegis ${UPD}`, `bun run /opt/aegis/src/cli/index.ts ${UPD}`, `cd /tmp && aegis ${UPD}`, `bash -c "aegis ${UPD}"`]) {
      const r = sh(c);
      expect(r.verdict).toBe("QUARANTINE");
      expect(r.rule_id).toBe("KAV-102");
    }
  });
  it("RU-302: status, and text that only mentions it, are not refused", () => {
    for (const c of ["aegis rules status", `echo "run aegis ${UPD}"`, `grep -n "${UPD}" docs/README.md`, `git commit -m "docs: aegis ${UPD}"`]) {
      expect(sh(c).verdict).toBe("PASS");
    }
  });
});
