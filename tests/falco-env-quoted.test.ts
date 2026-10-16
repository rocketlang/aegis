// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// Every proc.env value in a generated Falco ruleset is a quoted string. Falco reads an unquoted
// KAVACHOS_TRUST_MASK=0 as the value KAVACHOS_TRUST_MASK and a stray "=0", fails to compile the rule,
// and rejects the whole file: the trust_mask=0 (read-only) agent got a ruleset that never loaded.
// Reported by Andrey Lazarev's clean-bench run, 16 Oct 2026 (falco-rule-generator.ts:110).
// If falco is on PATH the files are also validated by Falco itself; otherwise that part is skipped.

import { describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { readFileSync } from "fs";
import { FALCO_DOMAINS, generateFalcoRules, q } from "../src/kernel/falco-rule-generator";

const DOMAINS = [...FALCO_DOMAINS];
const MASKS = [0, 1, 0xffffffff];
const falco = Bun.which("falco");

describe("generated Falco rules quote every proc.env value", () => {
  for (const domain of DOMAINS) {
    for (const mask of MASKS) {
      test(`${domain} trust_mask=${mask}`, () => {
        const { rules } = generateFalcoRules(domain, mask);
        // every operand of contains / startswith / endswith / != is a quoted string, not only proc.env
        const unquoted = [...rules.matchAll(/\b(contains|startswith|endswith|!=)\s+([^\s"][^\s)]*)/g)].map((m) => m[0]);
        expect(unquoted).toEqual([]);
      });
    }
  }

  test.skipIf(!falco)("falco --validate accepts every generated file", () => {
    const dir = mkdtempSync(join(tmpdir(), "falco-env-"));
    try {
      for (const domain of DOMAINS) {
        for (const mask of MASKS) {
          const file = join(dir, `${domain}-${mask}.yaml`);
          writeFileSync(file, generateFalcoRules(domain, mask).rules);
          const r = Bun.spawnSync([falco!, "--validate", file]);
          const out = r.stdout.toString() + r.stderr.toString();
          expect({ file: `${domain}-${mask}`, ok: out.includes(": Ok") && !out.includes("LOAD_ERR") }).toEqual({ file: `${domain}-${mask}`, ok: true });
        }
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("the generator builds every condition value through q()", () => {
  const src = readFileSync(new URL("../src/kernel/falco-rule-generator.ts", import.meta.url), "utf8");

  test("no hand-written operand in the source", () => {
    // an operator followed directly by a quote or a bare value means a value typed by hand
    const hand = src.split("\n").map((l, i) => [i + 1, l] as const)
      .filter(([, l]) => /^\s*condition:/.test(l))
      .filter(([, l]) => /\b(contains|startswith|endswith)\s+["A-Za-z/.!]/.test(l) || /(!=|[^!=<>]=)\s+"/.test(l))
      .map(([n, l]) => `${n}: ${l.trim()}`);
    expect(hand).toEqual([]);
  });

  test("q() quotes and escapes, and refuses a line break", () => {
    expect(q("KAVACHOS_TRUST_MASK=0")).toBe('"KAVACHOS_TRUST_MASK=0"');
    expect(q('a"b\\c')).toBe('"a\\"b\\\\c"');
    expect(() => q("a\nb")).toThrow();
  });
});

describe("domains", () => {
  test("freight is logistics", () => {
    const strip = (s: string) => s.replace(/^# .*$/m, "");
    expect(strip(generateFalcoRules("freight", 1).rules)).toBe(strip(generateFalcoRules("logistics", 1).rules));
    expect(generateFalcoRules("freight", 1).domain).toBe("logistics");
  });

  test("an unknown domain is refused, not quietly given the general rules", () => {
    expect(() => generateFalcoRules("bogus", 1)).toThrow(/unknown Falco domain 'bogus'/);
  });

  test("the CLI exits 2 on an unknown domain", () => {
    const r = Bun.spawnSync(["bun", new URL("../src/kavachos-cli.ts", import.meta.url).pathname, "rules", "--domain=bogus", "--trust-mask=1"]);
    expect(r.exitCode).toBe(2);
  });
});
