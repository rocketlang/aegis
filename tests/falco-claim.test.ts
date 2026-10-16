// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// The codex claim about Falco must be earned, not typed. Until 16 October 2026 codex.json said
// "✅ built … (maritime 7 rules, freight, general)" while the trust_mask=0 ruleset could not load in
// Falco, "freight" was not a domain the generator knew, and the rule count depended on the mask.
// This test holds the claim to the generator: the domains it names are exactly the generator's,
// it states no rule count, it names its proof, and the proof passes wherever falco is installed.

import { describe, expect, test } from "bun:test";
import { readFileSync } from "fs";
import { join } from "path";
import { FALCO_DOMAINS, FALCO_DOMAIN_ALIASES } from "../src/kernel/falco-rule-generator";
import { falcoSelfCheck } from "../src/kernel/falco-self-check";

const codex = JSON.parse(readFileSync(join(import.meta.dir, "..", "codex.json"), "utf8"));
const claim: string = codex.capabilities?.kavachos_falco_rules ?? findClaim(codex);

function findClaim(o: any): string {
  if (o && typeof o === "object") {
    if (typeof o.kavachos_falco_rules === "string") return o.kavachos_falco_rules;
    for (const v of Object.values(o)) { const c = findClaim(v); if (c) return c; }
  }
  return "";
}

describe("codex claim kavachos_falco_rules", () => {
  test("exists", () => expect(claim.length).toBeGreaterThan(0));

  test("names exactly the generator's domains and aliases", () => {
    const m = claim.match(/domains ([^;]+);/);
    expect(m).not.toBeNull();
    const named = m![1].replace(/\(alias ([a-z]+)\)/g, ", $1").split(",").map((s) => s.trim()).filter(Boolean).sort();
    expect(named).toEqual([...FALCO_DOMAINS, ...Object.keys(FALCO_DOMAIN_ALIASES)].sort());
  });

  test("states no rule count (it depends on the mask)", () => {
    expect(claim).not.toMatch(/\d+\s+rules/);
  });

  test("names its proof", () => {
    expect(claim).toContain("kavachos rules --self-check");
  });

  test("the proof holds (or says it could not check)", () => {
    const r = falcoSelfCheck();
    if (r.verdict === "could_not_check") {
      console.log("  falco not installed: the claim's proof could not be run here (not a pass)");
      return;
    }
    expect(r.files.filter((f) => f.ok !== true)).toEqual([]);
    expect(r.verdict).toBe("pass");
  });
});
