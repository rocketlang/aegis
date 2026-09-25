// SPDX-License-Identifier: AGPL-3.0-only
// AF-T-711 — the chain rehearsal. Both outcomes: with the shipped ruleset every step of
// the incident chain refuses-or-alerts; with a gutted ruleset the lexical step FAILS and
// all_pass goes false (the rehearsal cannot be stuck-on-green). Digest is reproducible
// and breaks on tamper.
import { describe, it, expect } from "bun:test";
import { readFileSync } from "fs";
import { runChainRehearsal } from "../src/redteam/chain-rehearsal";
import type { DestructiveRules } from "../src/kavach/destructive-verdict";

// The repo ruleset IS the live format since the eca0e68 reconciliation (repo == live).
const RULES = JSON.parse(readFileSync(new URL("../rules/destructive-rules.json", import.meta.url), "utf-8")) as DestructiveRules;
const TS = "2026-09-25T00:00:00.000Z";

describe("chain rehearsal (AF-T-711)", () => {
  it("every step of the incident chain refuses or alerts with the shipped rules", () => {
    const r = runChainRehearsal(RULES, TS);
    expect(r.steps.length).toBe(11);
    expect(r.steps.filter((s) => !s.pass)).toEqual([]);
    expect(r.all_pass).toBe(true);
  });

  it("a gutted destructive ruleset fails its step — the rehearsal detects a regressed gate", () => {
    const gutted = { ...RULES, bash_block_patterns: [] } as DestructiveRules;
    const r = runChainRehearsal(gutted, TS);
    const lex = r.steps.find((s) => s.id === "destructive-lexical")!;
    expect(lex.pass).toBe(false);
    expect(r.all_pass).toBe(false);
  });

  it("digest is reproducible for the same inputs and differs when a step changes", () => {
    const a = runChainRehearsal(RULES, TS);
    const b = runChainRehearsal(RULES, TS);
    expect(a.digest).toBe(b.digest);
    const c = runChainRehearsal({ ...RULES, bash_block_patterns: [] } as DestructiveRules, TS);
    expect(c.digest).not.toBe(a.digest);
  });
});
