// SPDX-License-Identifier: AGPL-3.0-only
// The harness and the two hardening measures, with EVERY outcome forced: a catchable miss
// under weak rules, a clean sheet under good rules, the SQL-comment evasion closed by the
// normalizer, the regex-ceiling variants reported (never as regressions), the echo false
// positive suppressed as inert, and — the safety boundary — an execution path re-arming the
// block. A harness stuck on "clean" cannot pass this suite. @rule:guards-assert-both-outcomes

import { describe, it, expect } from "bun:test";
import { runRedteam, isClean } from "../src/redteam/runner";
import { EXEMPLARS, CONTROLS, VARIANTS } from "../src/redteam/corpus";
import {
  destructiveVerdict, isInertDisplay, normalizeForMatch, type DestructiveRules,
} from "../src/kavach/destructive-verdict";

// Whitespace/case-tolerant, comment-aware-by-normalizer rules covering every exemplar.
const GOOD: DestructiveRules = {
  allowed_override_token: "HUMAN-DESTRUCTIVE-CONFIRMED-ANKR",
  bash_block_patterns: [
    { pattern: "DROP\\s+DATABASE", flags: "i", reason: "", severity: "CRITICAL" },
    { pattern: "DROP\\s+TABLE", flags: "i", reason: "", severity: "CRITICAL" },
    { pattern: "DROP\\s+SCHEMA", flags: "i", reason: "", severity: "CRITICAL" },
    { pattern: "TRUNCATE\\s+TABLE", flags: "i", reason: "", severity: "CRITICAL" },
    { pattern: "DELETE\\s+FROM\\s", flags: "i", reason: "", severity: "HIGH" },
    { pattern: "ALTER\\s+TABLE\\s+.*\\s+DROP\\s+COLUMN", flags: "i", reason: "", severity: "HIGH" },
    { pattern: "prisma\\s+migrate\\s+reset", flags: "i", reason: "", severity: "HIGH" },
    { pattern: "systemctl\\s+(stop|disable)\\s+postgresql", flags: "i", reason: "", severity: "CRITICAL" },
  ],
};

// Space-literal, case-sensitive: catches the tidy form, misses the tab and mixed-case rewrites.
const WEAK: DestructiveRules = {
  allowed_override_token: "HUMAN-DESTRUCTIVE-CONFIRMED-ANKR",
  bash_block_patterns: [
    { pattern: "DROP DATABASE", flags: "", reason: "", severity: "CRITICAL" },
    { pattern: "DROP TABLE", flags: "", reason: "", severity: "CRITICAL" },
    { pattern: "DROP SCHEMA", flags: "", reason: "", severity: "CRITICAL" },
    { pattern: "TRUNCATE TABLE", flags: "", reason: "", severity: "CRITICAL" },
    { pattern: "DELETE FROM ", flags: "", reason: "", severity: "HIGH" },
    { pattern: "ALTER TABLE .* DROP COLUMN", flags: "", reason: "", severity: "HIGH" },
    { pattern: "prisma migrate reset", flags: "", reason: "", severity: "HIGH" },
    { pattern: "systemctl stop postgresql", flags: "", reason: "", severity: "CRITICAL" },
  ],
};

describe("redteam harness — coverage and both outcomes", () => {
  it("only tries meaning-preserving variants (skips case on shell exemplars)", () => {
    const applicable = EXEMPLARS.reduce(
      (n, ex) => n + VARIANTS.filter((v) => v.appliesTo.includes(ex.kind)).length, 0);
    expect(runRedteam(GOOD).dangerousTried).toBe(applicable);
    expect(runRedteam(GOOD).controlsTried).toBe(CONTROLS.length);
  });

  it("is clean (catchable-ASR 0, no false positives) against good rules", () => {
    const r = runRedteam(GOOD);
    expect(r.catchableGaps).toEqual([]);
    expect(r.catchableAsr).toBe(0);
    expect(r.falsePositives).toEqual([]);
    expect(isClean(r)).toBe(true);
  });

  it("FINDS catchable gaps under weak rules — tab and mixed-case slip past", () => {
    const r = runRedteam(WEAK);
    expect(r.catchableGaps.length).toBeGreaterThan(0);
    expect(r.catchableAsr).toBeGreaterThan(0);
    expect(r.catchableGaps.some((g) => g.variant === "identity")).toBe(false); // tidy form still caught
    expect(isClean(r)).toBe(false);
  });

  it("always reports the regex-ceiling variants as ceiling, never as catchable gaps", () => {
    for (const rules of [GOOD, WEAK]) {
      const r = runRedteam(rules);
      expect(r.ceilingGaps.length).toBeGreaterThan(0);
      expect(r.ceilingGaps.every((g) => g.regexCeiling)).toBe(true);
      expect(r.catchableGaps.every((g) => !g.regexCeiling)).toBe(true);
    }
  });

  it("every regex-ceiling gap is within the semantic layer's reach (AF-T-104)", () => {
    // The whole point of ANU-I-006: what the denylist cannot catch, the semantic trigger can.
    const r = runRedteam(GOOD);
    expect(r.ceilingGaps.every((g) => g.semanticTrigger === true)).toBe(true);
  });
});

describe("normalizer closes the SQL-comment evasion (union, never a bypass)", () => {
  it("matches DROP/**/TABLE via the normalized view", () => {
    const v = destructiveVerdict("psql -c 'DROP/**/TABLE widgets'", GOOD);
    expect(v.kind).toBe("match");
    if (v.kind === "match") expect(v.via).toBe("normalized");
  });
  it("normalization only strips comments/whitespace — it cannot remove a raw block", () => {
    // `git push --force` style: the -- is a flag, not a SQL comment; raw still governs.
    expect(normalizeForMatch("psql -c 'DROP  TABLE  t'")).toBe("psql -c 'DROP TABLE t'");
  });
});

describe("inert-display FPR fix — narrow and safe", () => {
  it("suppresses a bare echo/printf that only names a keyword", () => {
    expect(destructiveVerdict("echo 'DROP TABLE t'", GOOD).kind).toBe("inert");
    expect(isInertDisplay("printf 'TRUNCATE TABLE t\\n'")).toBe(true);
    expect(runRedteam(GOOD).falsePositives).toEqual([]); // the echo/printf controls no longer flag
  });

  it("re-arms the block the moment an execution path appears (pipe/redirect/chain/subst)", () => {
    for (const cmd of [
      "echo 'DROP TABLE t' | psql",
      "echo 'DROP TABLE t' > migration.sql",
      "echo 'DROP TABLE t'; psql -f -",
      "echo \"$(psql -c 'DROP TABLE t')\"",
    ]) {
      expect(isInertDisplay(cmd)).toBe(false);
      expect(destructiveVerdict(cmd, GOOD).kind).toBe("match");
    }
  });

  it("a real destructive command is never inert", () => {
    expect(destructiveVerdict("psql -c 'DROP TABLE widgets'", GOOD).kind).toBe("match");
    expect(isInertDisplay("psql -c 'DROP TABLE widgets'")).toBe(false);
  });
});

import { scorePosture } from "../src/redteam/runner";
import { discoverRuleset } from "../src/cli/commands/redteam";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

describe("posture score (AF-T-202) — scores the ruleset, reports ceiling separately", () => {
  it("a whitespace/case-tolerant ruleset scores high (A) with 0 catchable gaps", () => {
    const p = scorePosture(runRedteam(GOOD));
    expect(p.score).toBeGreaterThanOrEqual(90);
    expect(p.grade).toBe("A");
    expect(p.evasionResistance).toBe(1); // no catchable evasion slipped past
  });
  it("a weak ruleset scores lower — catchable evasions drag evasion resistance down", () => {
    const weak = scorePosture(runRedteam(WEAK));
    const good = scorePosture(runRedteam(GOOD));
    expect(weak.score).toBeLessThan(good.score);
    expect(weak.evasionResistance).toBeLessThan(1);
  });
  it("ceiling exposure is reported, never folded into the score", () => {
    const p = scorePosture(runRedteam(GOOD));
    expect(p.ceilingExposure).toBeGreaterThan(0);                 // there ARE ceiling variants
    expect(p.ceilingCoveredBySemantic).toBe(p.ceilingExposure);   // ANKR's layer reaches them all
    expect(p.score).toBe(100);                                    // yet the ruleset still scores 100 — ceiling not penalised
  });
});

describe("target discovery (AF-T-201)", () => {
  it("finds a ruleset at each conventional location and null when absent", () => {
    const base = mkdtempSync(join(tmpdir(), "rt-target-"));
    try {
      expect(discoverRuleset(base)).toBeNull();
      mkdirSync(join(base, ".aegis"), { recursive: true });
      writeFileSync(join(base, ".aegis", "destructive-rules.json"), "{}");
      expect(discoverRuleset(base)).toBe(join(base, ".aegis", "destructive-rules.json"));
    } finally {
      rmSync(base, { recursive: true, force: true });
    }
  });
});

import { measurePrecision } from "../src/redteam/runner";
import { BENIGN_CORPUS } from "../src/redteam/benign-corpus";

describe("benign corpus precision (AF-T-204)", () => {
  const corpus = BENIGN_CORPUS.map((b) => ({ cmd: b.cmd, category: b.category }));
  it("GOOD (precise) rules refuse NO benign command — FPR 0", () => {
    const p = measurePrecision(GOOD, corpus);
    expect(p.tried).toBe(BENIGN_CORPUS.length);
    expect(p.falsePositives).toEqual([]);
    expect(p.fpr).toBe(0);
  });
  it("a broad TRUNCATE rule over-blocks the shell `truncate` — the corpus catches it", () => {
    const broad: typeof GOOD = {
      allowed_override_token: "X",
      bash_block_patterns: [{ pattern: "TRUNCATE\\s+", flags: "i", reason: "", severity: "CRITICAL" }],
    };
    const p = measurePrecision(broad, corpus);
    expect(p.falsePositives.length).toBeGreaterThan(0);
    expect(p.falsePositives.some((fp) => fp.cmd.startsWith("truncate -s 100M"))).toBe(true);
    expect(p.byCategory.file.falsePositives).toBeGreaterThan(0);
  });
  it("runRedteam attaches precision only when a corpus is supplied", () => {
    expect(runRedteam(GOOD).precision).toBeUndefined();
    expect(runRedteam(GOOD, { precisionCorpus: corpus }).precision?.tried).toBe(BENIGN_CORPUS.length);
  });
});
