// SPDX-License-Identifier: AGPL-3.0-only
// Guard (FP-021: a lesson compiled into a constraint): hook stdin arrives as a SOCKET, where
// readFileSync("/dev/stdin") throws ENXIO and the hook silently reads nothing. Every aegis gate
// was blind 2026-09-25 → 2026-09-29 this way while pipe-fed tests stayed green.
//
// The files still on /dev/stdin are pinned EXACTLY. Each is held on purpose:
//   check-destructive, check-spawn — founder ruling pending (perm_mask escalation would lock
//     sessions: stage-2 replay 2026-09-29); check-chitta — rides with them (content scan);
//   session-start — another lane holds uncommitted edits.
// Re-arming one = remove it from HELD in the same commit. Adding a NEW /dev/stdin reader fails.
import { describe, it, expect } from "bun:test";
import { readdirSync, readFileSync, statSync } from "fs";
import { join } from "path";

const HELD = [
  "src/cli/commands/check-chitta.ts",
  "src/cli/commands/check-destructive.ts",
  "src/cli/commands/check-spawn.ts",
  "src/hooks/session-start.ts",
];

function walk(dir: string, out: string[] = []): string[] {
  for (const n of readdirSync(dir)) {
    const p = join(dir, n);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (p.endsWith(".ts")) out.push(p);
  }
  return out;
}

describe("hook stdin guard", () => {
  it("only the explicitly HELD files still read /dev/stdin", () => {
    const root = join(import.meta.dir, "..");
    const offenders = walk(join(root, "src"))
      .filter((p) => readFileSync(p, "utf-8").includes('readFileSync("/dev/stdin"'))
      .map((p) => p.slice(root.length + 1))
      .sort();
    expect(offenders).toEqual(HELD);
  });
});
