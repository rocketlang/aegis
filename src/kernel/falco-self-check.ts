// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// The proof behind the codex claim "kavachos_falco_rules": every domain × trust_mask ruleset the
// generator can produce is handed to Falco itself (falco --validate) and must be accepted. Until
// 16 October 2026 that claim was a hand-written ✅ while the trust_mask=0 file could not load.
// No falco on the box = verdict "could_not_check", never a pass.

import { mkdtempSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { spawnSync } from "child_process";
import { FALCO_DOMAINS, generateFalcoRules } from "./falco-rule-generator";

// 0 = the read-only class (the only mask with its own rule), 1 = minimal, all bits = widest.
export const SELF_CHECK_MASKS = [0, 1, 0xffffffff] as const;

export interface FalcoSelfCheck {
  schema: "kavachos-falco-selfcheck-v1";
  at: string;
  validated_by: string | null;
  verdict: "pass" | "fail" | "could_not_check";
  files: { domain: string; trust_mask: number; rule_count: number; ok: boolean | null; error?: string }[];
}

function findFalco(): string | null {
  const explicit = process.env.FALCO;
  if (explicit) return explicit;
  const r = spawnSync("sh", ["-c", "command -v falco"], { encoding: "utf8" });
  return r.status === 0 && r.stdout.trim() ? r.stdout.trim() : null;
}

export function falcoSelfCheck(falco: string | null = findFalco()): FalcoSelfCheck {
  let validatedBy: string | null = null;
  if (falco) {
    const v = spawnSync(falco, ["--version"], { encoding: "utf8" });
    const m = `${v.stdout}${v.stderr}`.match(/Falco version:\s*([^\s]+)/);
    validatedBy = v.status === 0 ? `falco ${m ? m[1] : "(version unknown)"}` : null;
  }

  const dir = mkdtempSync(join(tmpdir(), "kavachos-falco-selfcheck-"));
  const files: FalcoSelfCheck["files"] = [];
  try {
    for (const domain of FALCO_DOMAINS) {
      for (const mask of SELF_CHECK_MASKS) {
        const set = generateFalcoRules(domain, mask);
        const entry: FalcoSelfCheck["files"][number] = { domain, trust_mask: mask, rule_count: set.rule_count, ok: null };
        if (validatedBy) {
          const file = join(dir, `${domain}-${mask}.yaml`);
          writeFileSync(file, set.rules);
          const r = spawnSync(falco!, ["--validate", file], { encoding: "utf8" });
          const out = `${r.stdout}${r.stderr}`;
          entry.ok = r.status === 0 && out.includes(": Ok") && !out.includes("LOAD_ERR");
          if (!entry.ok) entry.error = (out.match(/LOAD_ERR[^\n]*/) ?? [`falco exit ${r.status}`])[0];
        }
        files.push(entry);
      }
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }

  const verdict = !validatedBy ? "could_not_check" : files.every((f) => f.ok) ? "pass" : "fail";
  return { schema: "kavachos-falco-selfcheck-v1", at: new Date().toISOString(), validated_by: validatedBy, verdict, files };
}
