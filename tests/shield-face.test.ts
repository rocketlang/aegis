// SPDX-License-Identifier: AGPL-3.0-only
// AF-T-301 — the shield face, both outcomes forced: a well-formed ruleset catches every
// representative injection + persistence seed and their lexical/path variants; a weak ruleset
// misses them and the face reports it. @rule:guards-assert-both-outcomes
import { describe, it, expect } from "bun:test";
import { runShieldFace, shieldFaceClean } from "../src/redteam/shield-face";
import type { ShieldRules } from "../src/shield/injection-detector";

const STRONG: ShieldRules = {
  version: "test",
  injection_patterns: [
    { id: "INJ-001", pattern: "ignore\\s+(all\\s+)?previous\\s+instructions", flags: "i", severity: "QUARANTINE", reason: "" },
    { id: "INJ-002", pattern: "forget\\s+(all\\s+)?your\\s+instructions", flags: "i", severity: "QUARANTINE", reason: "" },
    { id: "INJ-003", pattern: "disregard\\s+(all\\s+)?previous", flags: "i", severity: "QUARANTINE", reason: "" },
    { id: "INJ-004", pattern: "your\\s+new\\s+(system\\s+)?instructions?", flags: "i", severity: "QUARANTINE", reason: "" },
    { id: "INJ-005", pattern: "override\\s+your\\s+(safety|security)", flags: "i", severity: "QUARANTINE", reason: "" },
    { id: "INJ-010", pattern: "\\bDAN\\b.*no\\s+longer\\s+bound", flags: "i", severity: "QUARANTINE", reason: "" },
  ],
  persistence_targets: ["/.bashrc", "/.ssh/authorized_keys", "/etc/cron", "/etc/systemd/system/", "/.claude/settings.json"],
  credential_paths: [],
  exfil_commands: [],
  large_read_threshold_bytes: 100000,
  exfil_window_tool_calls: 5,
};

const WEAK: ShieldRules = { ...STRONG, injection_patterns: [], persistence_targets: [] };

describe("shield face (AF-T-301)", () => {
  it("STRONG rules catch every injection + persistence seed and all variants — clean", () => {
    const r = runShieldFace(STRONG);
    expect(r.injection.misses).toEqual([]);
    expect(r.injection.robustnessGaps).toEqual([]);
    expect(r.persistence.misses).toEqual([]);
    expect(r.persistence.variantGaps).toEqual([]);
    expect(shieldFaceClean(r)).toBe(true);
  });

  it("WEAK rules miss the seeds — the face reports it as not-clean", () => {
    const r = runShieldFace(WEAK);
    expect(r.injection.misses.length).toBe(6);
    expect(r.persistence.misses.length).toBe(5);
    expect(shieldFaceClean(r)).toBe(false);
  });

  it("benign injection text is reported as precision, never as a miss (fuzzy, non-gating)", () => {
    const r = runShieldFace(STRONG);
    // INJ-003 'disregard previous' is broad; the benign set may trip it — that is a REPORTED
    // false positive, and it must NOT flip shieldFaceClean (only misses/gaps do).
    expect(shieldFaceClean(r)).toBe(true);
    expect(Array.isArray(r.injection.falsePositives)).toBe(true);
  });
});
