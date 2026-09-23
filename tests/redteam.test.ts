// SPDX-License-Identifier: AGPL-3.0-only
// The harness must (a) find a real gap in a deliberately weak rule set, and (b) report a
// clean sheet against a rule set that covers the exemplars — both outcomes forced, so a
// harness that always says "clean" cannot pass. @rule:guards-assert-both-outcomes

import { describe, it, expect } from "bun:test";
import { runRedteam } from "../src/redteam/runner";
import { EXEMPLARS, CONTROLS, VARIANTS } from "../src/redteam/corpus";
import type { DestructiveRules } from "../src/kavach/destructive-verdict";

// A rule set strong enough to catch every exemplar under every variant: case-insensitive,
// whitespace-tolerant patterns for each keyword pair the exemplars use.
const STRONG: DestructiveRules = {
  allowed_override_token: "HUMAN-DESTRUCTIVE-CONFIRMED-ANKR",
  bash_block_patterns: [
    { pattern: "DROP\\s+DATABASE", flags: "i", reason: "", severity: "CRITICAL" },
    { pattern: "DROP\\s+TABLE", flags: "i", reason: "", severity: "CRITICAL" },
    { pattern: "DROP\\s+SCHEMA", flags: "i", reason: "", severity: "CRITICAL" },
    { pattern: "TRUNCATE\\s", flags: "i", reason: "", severity: "CRITICAL" },
    { pattern: "DELETE\\s+FROM\\s", flags: "i", reason: "", severity: "HIGH" },
    { pattern: "ALTER\\s+TABLE\\s+.*\\s+DROP\\s+COLUMN", flags: "i", reason: "", severity: "HIGH" },
    { pattern: "prisma\\s+migrate\\s+reset", flags: "i", reason: "", severity: "HIGH" },
    { pattern: "systemctl\\s+(stop|disable)\\s+postgresql", flags: "i", reason: "", severity: "CRITICAL" },
  ],
};

// A weak rule set: space-literal (no \s), case-sensitive. It catches the tidy form but must
// miss the tab and mixed-case variants — that miss is exactly what the harness exists to find.
const WEAK: DestructiveRules = {
  allowed_override_token: "HUMAN-DESTRUCTIVE-CONFIRMED-ANKR",
  bash_block_patterns: [
    { pattern: "DROP DATABASE", flags: "", reason: "", severity: "CRITICAL" },
    { pattern: "DROP TABLE", flags: "", reason: "", severity: "CRITICAL" },
    { pattern: "DROP SCHEMA", flags: "", reason: "", severity: "CRITICAL" },
    { pattern: "TRUNCATE ", flags: "", reason: "", severity: "CRITICAL" },
    { pattern: "DELETE FROM ", flags: "", reason: "", severity: "HIGH" },
    { pattern: "ALTER TABLE .* DROP COLUMN", flags: "", reason: "", severity: "HIGH" },
    { pattern: "prisma migrate reset", flags: "", reason: "", severity: "HIGH" },
    { pattern: "systemctl stop postgresql", flags: "", reason: "", severity: "CRITICAL" },
  ],
};

describe("redteam robustness harness", () => {
  it("tries every exemplar under every variant", () => {
    const r = runRedteam(STRONG);
    expect(r.dangerousTried).toBe(EXEMPLARS.length * VARIANTS.length);
    expect(r.controlsTried).toBe(CONTROLS.length);
  });

  it("ASR is 0 against a whitespace/case-tolerant rule set — no variant slips past", () => {
    const r = runRedteam(STRONG);
    expect(r.gaps).toEqual([]);
    expect(r.asr).toBe(0);
  });

  it("FINDS gaps in a weak rule set — the tab and mixed-case variants slip past", () => {
    const r = runRedteam(WEAK);
    expect(r.gaps.length).toBeGreaterThan(0);
    expect(r.asr).toBeGreaterThan(0);
    // the identity variant is the tidy form; it must still be caught even by the weak rules
    expect(r.gaps.some((g) => g.variant === "identity")).toBe(false);
    // the misses must be the meaning-preserving rewrites, and each carries its justification
    expect(r.gaps.every((g) => g.preserves.length > 0)).toBe(true);
  });

  it("FINDS a false positive — a substring rule over-blocks a benign echo that names a keyword", () => {
    // A naive substring/regex gate cannot tell `echo 'DROP TABLE ...'` from a real statement.
    // The harness surfaces that as over-blocking; both a miss (above) and an over-block are
    // forced outcomes, so a harness stuck on "clean" cannot pass this suite.
    const r = runRedteam(STRONG);
    expect(r.falsePositives.length).toBeGreaterThan(0);
    expect(r.fpr).toBeGreaterThan(0);
    expect(r.falsePositives.some((fp) => fp.control.startsWith("echo "))).toBe(true);
  });

  it("does not flag a keyword-free benign control", () => {
    // `systemctl status postgresql` names no destructive keyword and must never be refused.
    const r = runRedteam(STRONG);
    expect(r.falsePositives.some((fp) => fp.control.includes("systemctl status"))).toBe(false);
  });
});
