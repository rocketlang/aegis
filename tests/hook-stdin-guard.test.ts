// SPDX-License-Identifier: AGPL-3.0-only
// Guard (FP-021: a lesson compiled into a constraint): hook stdin arrives as a SOCKET, where
// readFileSync("/dev/stdin") throws ENXIO and the hook silently reads nothing. Every aegis gate
// was blind 2026-09-25 → 2026-09-29 this way while pipe-fed tests stayed green.
//
// The files still on /dev/stdin are pinned EXACTLY. Each is held on purpose:
//   check-chitta — held (content scan); session-start — another lane holds uncommitted edits.
// Re-arming one = remove it from HELD in the same commit. Adding a NEW /dev/stdin reader fails.
//
// check-destructive left this list on 2026-10-02: it reads fd 0, runs its pattern level
// only (the perm_mask levels are a separate switch, off by default), and is tested on a
// real socket in destructive-gate-armed.test.ts.
//
// check-spawn left it in 2.6.0, the same way: it reads fd 0 through cli/hook-input.ts, and
// its Level 0 valve check — the perm_mask escalation it was held for (stage-2 replay
// 2026-09-29) — runs only when kavach.perm_mask_levels is "live", off by default. It is
// tested on a real socket in budget-spawn-hardening.test.ts.
import { describe, it, expect } from "bun:test";
import { readdirSync, readFileSync, statSync } from "fs";
import { join } from "path";

const HELD = [
  "src/cli/commands/check-chitta.ts",
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
