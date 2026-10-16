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
import { generateFalcoRules } from "../src/kernel/falco-rule-generator";

const DOMAINS = ["maritime", "logistics", "ot", "finance", "general"];
const MASKS = [0, 1, 0xffffffff];
const falco = Bun.which("falco");

describe("generated Falco rules quote every proc.env value", () => {
  for (const domain of DOMAINS) {
    for (const mask of MASKS) {
      test(`${domain} trust_mask=${mask}`, () => {
        const { rules } = generateFalcoRules(domain, mask);
        const unquoted = [...rules.matchAll(/proc\.env contains\s+([^\s"][^\s)]*)/g)].map((m) => m[1]);
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
