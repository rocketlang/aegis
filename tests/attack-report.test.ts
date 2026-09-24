// SPDX-License-Identifier: AGPL-3.0-only
// AF-T-203 — the report artifact: provenance (ruleset hash), a reproducible content digest,
// and tamper-evidence (an edit breaks the digest). Both outcomes forced. @rule:guards-assert-both-outcomes
import { describe, it, expect } from "bun:test";
import { runRedteam } from "../src/redteam/runner";
import { buildAttackReport, verifyAttackReport, ATTACK_REPORT_SCHEMA } from "../src/redteam/report";
import type { DestructiveRules } from "../src/kavach/destructive-verdict";

const RULES: DestructiveRules = {
  allowed_override_token: "HUMAN-DESTRUCTIVE-CONFIRMED-ANKR",
  bash_block_patterns: [
    { pattern: "DROP\\s+TABLE", flags: "i", reason: "", severity: "CRITICAL" },
    { pattern: "DELETE\\s+FROM\\s", flags: "i", reason: "", severity: "HIGH" },
  ],
};
const content = JSON.stringify(RULES);

describe("attack report artifact (AF-T-203)", () => {
  it("carries schema, ruleset provenance hash, posture, and a digest", () => {
    const a = buildAttackReport(runRedteam(RULES), { target: "acme-corp", rulesetContent: content, now: new Date("2026-09-24T00:00:00Z") });
    expect(a.schema).toBe(ATTACK_REPORT_SCHEMA);
    expect(a.rulesetSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(a.digest).toMatch(/^[0-9a-f]{64}$/);
    expect(a.posture.grade).toMatch(/^[A-F]$/);
    expect(a.target).toBe("acme-corp");
  });

  it("is reproducible — same report + ruleset + timestamp → same digest", () => {
    const now = new Date("2026-09-24T00:00:00Z");
    const a = buildAttackReport(runRedteam(RULES), { target: "x", rulesetContent: content, now });
    const b = buildAttackReport(runRedteam(RULES), { target: "x", rulesetContent: content, now });
    expect(a.digest).toBe(b.digest);
    expect(verifyAttackReport(a).intact).toBe(true);
  });

  it("detects tampering — any edit after the fact breaks the digest", () => {
    const a = buildAttackReport(runRedteam(RULES), { target: "x", rulesetContent: content, now: new Date("2026-09-24T00:00:00Z") });
    const tampered = { ...a, posture: { ...a.posture, score: 100, grade: "A" as const } };
    expect(verifyAttackReport(tampered).intact).toBe(false);
  });
});
