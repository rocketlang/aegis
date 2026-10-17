// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.

// aegis rules status          compare the installed destructive rules with this package's
// aegis rules update [--dry]  bring the installed copy up to this package's (a PERSON runs it)
//
// `aegis init` copies rules/destructive-rules.json into the aegis home once and never again, so an
// upgrade changes the code and leaves the gate on the rules it was installed with. On the author's
// own box the copy stayed at the 2026-10-02 rules after 2.5.0 had bounded five of them: their `.*`
// reached from one command into the next, and harmless lines were refused (found 2026-10-17).
//
// WHAT UPDATE DOES
//   - every pattern of this package's file, in its order;
//   - then every installed pattern this package does not have and has never shipped (the
//     installer's own), kept as written;
//   - an installed pattern this package shipped once and has since replaced (_retired_patterns)
//     is dropped: its replacement is in the first list.
//   The old file is kept beside it (.bak-<time>) and the new one is written whole, then renamed.
//
// WHY A PERSON: the gate's rules are what stand between an agent and an unrecoverable command. As a
// tool call, this would let an agent copy a rules file it can edit over the one it cannot (KAV-102,
// refused by the shield). `status` reads only and is anyone's.
//
// Exit: 0 current (status) or updated / nothing to do (update) · 1 differs (status) or refused, with
// the reason (update) · 3 broke.

import { existsSync, lstatSync, readFileSync, renameSync, writeFileSync, copyFileSync } from "fs";
import { join } from "path";
import { getAegisDir } from "../../core/config";

interface Rule { pattern: string; flags?: string; reason?: string; severity?: string }
interface RulesFile { bash_block_patterns: Rule[]; _version?: string; _retired_patterns?: string[]; [k: string]: unknown }

export interface RulesPlan {
  installedVersion: string | null;
  packageVersion: string | null;
  current: Rule[];   // in both
  missing: Rule[];   // this package has, the installed copy does not
  outdated: Rule[];  // installed, shipped once, since replaced
  local: Rule[];     // installed, never shipped: the installer's own, kept
}

const say = (s: string) => process.stdout.write(`[rules] ${s}\n`);
const fail = (s: string, code = 1): never => { process.stderr.write(`[rules] ${s}\n`); process.exit(code); };

export function packageRulesPath(): string {
  return join(import.meta.dir, "../../../rules/destructive-rules.json");
}
export function installedRulesPath(): string {
  return join(getAegisDir(), "destructive-rules.json");
}

function load(path: string): RulesFile {
  const parsed = JSON.parse(readFileSync(path, "utf-8"));
  if (!parsed || !Array.isArray(parsed.bash_block_patterns)) throw new Error(`${path} has no bash_block_patterns list`);
  return parsed as RulesFile;
}

/** Pure: what an update would do. */
export function planRules(installed: RulesFile, pkg: RulesFile): RulesPlan {
  const shipped = new Set(pkg.bash_block_patterns.map((r) => r.pattern));
  const retired = new Set(pkg._retired_patterns ?? []);
  const have = new Set(installed.bash_block_patterns.map((r) => r.pattern));
  return {
    installedVersion: installed._version ?? null,
    packageVersion: pkg._version ?? null,
    current: pkg.bash_block_patterns.filter((r) => have.has(r.pattern)),
    missing: pkg.bash_block_patterns.filter((r) => !have.has(r.pattern)),
    outdated: installed.bash_block_patterns.filter((r) => !shipped.has(r.pattern) && retired.has(r.pattern)),
    local: installed.bash_block_patterns.filter((r) => !shipped.has(r.pattern) && !retired.has(r.pattern)),
  };
}

/** Pure: the file an update writes. The package's own keys, its patterns, then the installer's. */
export function mergedRules(installed: RulesFile, pkg: RulesFile): RulesFile {
  const { local } = planRules(installed, pkg);
  return { ...pkg, bash_block_patterns: [...pkg.bash_block_patterns, ...local] };
}

const short = (r: Rule) => `${r.pattern.length > 90 ? r.pattern.slice(0, 87) + "..." : r.pattern}`;

function report(plan: RulesPlan): void {
  say(`installed ${plan.installedVersion ?? "(no version)"} · this package ${plan.packageVersion ?? "(no version)"}`);
  say(`${plan.current.length} pattern(s) the same`);
  for (const r of plan.outdated) say(`  OUTDATED (replaced since): ${short(r)}`);
  for (const r of plan.missing) say(`  NOT INSTALLED: ${short(r)}`);
  for (const r of plan.local) say(`  YOURS (kept): ${short(r)}`);
}

export default async function rules(args: string[]): Promise<void> {
  const sub = args[0] ?? "status";
  const pkgPath = packageRulesPath();
  const livePath = installedRulesPath();
  try {
    if (!existsSync(pkgPath)) fail(`this package has no rules file at ${pkgPath}`, 3);
    const pkg = load(pkgPath);

    if (sub === "status") {
      if (!existsSync(livePath)) { say(`no installed rules at ${livePath} — the gate has nothing to read. A person runs: aegis rules update`); process.exit(1); }
      const plan = planRules(load(livePath), pkg);
      report(plan);
      const differs = plan.outdated.length + plan.missing.length > 0;
      say(differs ? "differs from this package — a person runs: aegis rules update --dry, then aegis rules update" : "current");
      process.exit(differs ? 1 : 0);
    }

    if (sub !== "update") fail(`unknown: aegis rules ${sub} (status | update [--dry])`);
    const dry = args.includes("--dry");

    if (!existsSync(livePath)) {
      if (dry) { say(`would install ${pkgPath} at ${livePath}`); process.exit(0); }
      copyFileSync(pkgPath, livePath);
      say(`installed ${livePath} (${pkg.bash_block_patterns.length} patterns)`);
      process.exit(0);
    }
    if (lstatSync(livePath).isSymbolicLink()) fail(`${livePath} is a link; not written through. Look at what it points to, and replace it by hand.`);

    let installed: RulesFile;
    try { installed = load(livePath); }
    catch (e: any) { fail(`${livePath} does not read as a rules file (${e.message}); not replaced — look at it first`); }
    const plan = planRules(installed!, pkg);
    report(plan);
    if (plan.outdated.length + plan.missing.length === 0) { say("already current; nothing written"); process.exit(0); }
    if (dry) { say("--dry: nothing written"); process.exit(0); }

    const merged = mergedRules(installed!, pkg);
    const stamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\..*$/, "");
    const backup = `${livePath}.bak-${stamp}`;
    copyFileSync(livePath, backup);
    const tmp = `${livePath}.tmp-${process.pid}`;
    writeFileSync(tmp, JSON.stringify(merged, null, 2) + "\n", { mode: lstatSync(livePath).mode & 0o777 });
    load(tmp); // it reads back as a rules file, or nothing is replaced
    renameSync(tmp, livePath);
    say(`updated ${livePath}: ${merged.bash_block_patterns.length} patterns (${plan.local.length} of yours kept); the old file is ${backup}`);
    process.exit(0);
  } catch (e: any) {
    fail(`broke: ${e?.message ?? e}`, 3);
  }
}
