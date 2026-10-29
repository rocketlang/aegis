// SPDX-License-Identifier: AGPL-3.0-only
// AEG-T044: cost credited to the repositories a session's messages touched (2026-10-29).
// Run under a scratch HOME: the parser reads ~/.aegis config.
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { costByRepo, pathsTouched, makeRepoOf, NO_FILE } from "../src/monitor/repo-attribution";

let root: string, box: string, tr: string;
const msg = (sid: string, ts: string, tools: any[], out = 1000) => JSON.stringify({
  type: "assistant", sessionId: sid, timestamp: ts,
  message: { role: "assistant", model: "claude-haiku-5-5", usage: { input_tokens: 0, output_tokens: out }, content: tools },
}) + "\n";
const read = (p: string) => ({ type: "tool_use", name: "Read", input: { file_path: p } });
const bash = (c: string) => ({ type: "tool_use", name: "Bash", input: { command: c } });

beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), "aegis-repo-cost-"));
  box = join(root, "box");                       // a repository holding two nested repositories
  for (const d of ["", "alpha", "beta", "beta/src", "plain"]) mkdirSync(join(box, d), { recursive: true });
  for (const d of ["", "alpha", "beta"]) mkdirSync(join(box, d, ".git"), { recursive: true });
  tr = join(root, "projects", "-box");
  mkdirSync(join(tr, "s1", "subagents"), { recursive: true });
  const T = "2026-10-01T10:00:0";
  writeFileSync(join(tr, "s1.jsonl"),
    msg("S1", T + "0Z", []) +                                         // nothing touched yet
    msg("S1", T + "1Z", [read(join(box, "alpha", "a.ts"))]) +          // alpha
    msg("S1", T + "2Z", []) +                                         // still alpha
    msg("S1", T + "3Z", [bash(`cd ${join(box, "beta")} && ls ${join(box, "beta", "src", "gone.ts")}`)]) + // beta (a missing file)
    msg("S1", T + "4Z", [read(join(box, "alpha", "x")), read(join(box, "beta", "y"))]) +                // split
    msg("S1", T + "5Z", [read(join(box, "plain", "notes.md"))]));      // the outer repository
  writeFileSync(join(tr, "s1", "subagents", "agent-1.jsonl"), msg("S1", T + "6Z", [read("/nonexistent-root-xyz/file")]));
});
afterAll(() => rmSync(root, { recursive: true, force: true }));

describe("cost by repository", () => {
  test("paths come from file tools and from absolute paths in Bash commands", () => {
    const d = JSON.parse(msg("S", "2026-10-29T00:00:00Z", [read("/a/b.ts"), bash("cd /x/y && grep -n foo /z/w.txt | head")]));
    expect(pathsTouched(d)).toEqual(["/a/b.ts", "/x/y", "/z/w.txt"]);
  });

  test("the nearest .git wins; a missing file falls back to its nearest existing folder", () => {
    const repoOf = makeRepoOf();
    expect(repoOf(join(box, "beta", "src", "gone.ts"))).toBe(join(box, "beta"));
    expect(repoOf(join(box, "plain", "notes.md"))).toBe(box);
    expect(repoOf("/nonexistent-root-xyz/file")).toBe(null);
    expect(repoOf(join(box, "beta") + "/")).toBe(join(box, "beta"));   // a trailing slash is the same repository
  });

  test("each record goes to the repository its message touched, else the session's last one", () => {
    const { rows, total_usd } = costByRepo([join(root, "projects")]);
    const by = Object.fromEntries(rows.map((r) => [r.repo, r]));
    expect(by[NO_FILE].records).toBe(1);
    expect(by[join(box, "alpha")].records).toBe(2.5);   // 1 + 1 (no file, still alpha) + half of the split
    expect(by[join(box, "beta")].records).toBe(1.5);
    // The subagent's path is outside any repository: it keeps the session's last repository (the outer one).
    expect(by[box].records).toBe(2);
    const sum = rows.reduce((s, r) => s + r.cost_usd, 0);
    expect(Math.abs(sum - total_usd)).toBeLessThan(1e-9);
    expect(total_usd).toBeGreaterThan(0);
  });

  test("a since-time leaves out older records", () => {
    const { total_usd, rows } = costByRepo([join(root, "projects")], { sinceMs: Date.parse("2026-10-01T10:00:05Z") });
    expect(rows.reduce((s, r) => s + r.records, 0)).toBe(2);
    expect(total_usd).toBeGreaterThan(0);
  });
});
