// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// AEGIS — cost by the repositories a session worked in (AEG-T044, 2026-10-29)
// Almost every session on a shared box starts in one folder, so the session's start folder says little about
// where the money went. This reads the session transcripts on disk and credits each usage record to the git
// repository of the files that message touched (Read/Edit/Write/Grep/Glob paths, and absolute paths inside
// Bash commands). A message that touches no file is credited to the session's last repository, or to
// "(no file touched yet)". Costs come from the monitor's own parser, so they agree with usage_log.
// Read-only. Limited to the transcripts the CLI still keeps (Claude Code removes them after 30 days).

import { existsSync, readdirSync, readFileSync, statSync } from "fs";
import { dirname, join, resolve } from "path";
import { parseLine } from "./parser";

export const NO_FILE = "(no file touched yet)";

const PATH_KEYS = ["file_path", "path", "notebook_path"];
const ABS_PATH = /(?:^|[\s"'=:(])(\/[A-Za-z0-9._@+-][^\s"'`;|&<>()]*)/g;

// The nearest folder holding .git (a directory, or a file in a worktree), cached; null outside any repository.
export function makeRepoOf(cache = new Map<string, string | null>()) {
  return function repoOf(p: string): string | null {
    let d = resolve(p);   // "/a/b/" and "/a/b/./c/.." name the same folder as "/a/b"
    // Walk up to an existing folder first: a path may name a file that is gone, or never existed.
    while (d !== "/" && !existsSync(d)) d = dirname(d);
    try { if (!statSync(d).isDirectory()) d = dirname(d); } catch { return null; }
    const seen: string[] = [];
    let found: string | null = null;
    for (let x = d; ; x = dirname(x)) {
      if (cache.has(x)) { found = cache.get(x)!; break; }
      seen.push(x);
      if (existsSync(join(x, ".git"))) { found = x; break; }
      if (x === "/") break;
    }
    for (const s of seen) cache.set(s, found);
    return found;
  };
}

// The paths one transcript line touches, from its tool calls.
export function pathsTouched(data: any): string[] {
  const out: string[] = [];
  const content = data?.message?.content;
  if (!Array.isArray(content)) return out;
  for (const c of content) {
    if (c?.type !== "tool_use" || !c.input) continue;
    for (const k of PATH_KEYS) if (typeof c.input[k] === "string" && c.input[k].startsWith("/")) out.push(c.input[k]);
    if (typeof c.input.command === "string") for (const m of c.input.command.matchAll(ABS_PATH)) out.push(m[1]);
  }
  return out;
}

export interface RepoRow { repo: string; cost_usd: number; records: number; sessions: number }

export function costByRepo(transcriptRoots: string[], opts: { sinceMs?: number; repoOf?: (p: string) => string | null } = {}): { rows: RepoRow[]; total_usd: number; files: number } {
  const repoOf = opts.repoOf ?? makeRepoOf();
  const since = opts.sinceMs ?? 0;
  const acc = new Map<string, { cost: number; records: number; sessions: Set<string> }>();
  const lastRepo = new Map<string, string>();
  let total = 0, files = 0;
  const credit = (repo: string, sid: string, cost: number, recs: number) => {
    const a = acc.get(repo) ?? { cost: 0, records: 0, sessions: new Set<string>() };
    a.cost += cost; a.records += recs; a.sessions.add(sid); acc.set(repo, a);
  };
  const walk = (dir: string, depth: number): string[] => {
    if (depth > 4) return [];
    let found: string[] = [];
    try {
      for (const e of readdirSync(dir, { withFileTypes: true })) {
        const full = join(dir, e.name);
        if (e.isDirectory()) found = found.concat(walk(full, depth + 1));
        else if (e.name.endsWith(".jsonl")) { try { if (statSync(full).mtimeMs >= since) found.push(full); } catch { /* gone */ } }
      }
    } catch { /* unreadable */ }
    return found;
  };
  // A session's lines are spread over its own file and its subagents' files: gather the few facts each line
  // carries, then replay them in time order, so "the session's last repository" means the last in time.
  const events: Array<{ sid: string; ts: number; repos: string[]; cost: number | null }> = [];
  for (const root of transcriptRoots) {
    if (!existsSync(root)) continue;
    for (const f of walk(root, 0)) {
      files++;
      let text = "";
      try { text = readFileSync(f, "utf8"); } catch { continue; }
      for (const line of text.split("\n")) {
        if (!line.startsWith("{")) continue;
        let data: any;
        try { data = JSON.parse(line); } catch { continue; }
        const sid: string | undefined = data.sessionId;
        if (!sid) continue;
        const repos = [...new Set(pathsTouched(data).map(repoOf).filter((r): r is string => !!r))];
        const u = parseLine(line, "").usage;
        if (!repos.length && !u) continue;
        const ts = Date.parse(u?.timestamp ?? data.timestamp ?? "");
        events.push({ sid, ts: Number.isFinite(ts) ? ts : 0, repos, cost: u ? u.estimated_cost_usd || 0 : null });
      }
    }
  }
  events.sort((a, b) => a.ts - b.ts);
  for (const e of events) {
    if (e.repos.length) lastRepo.set(e.sid, e.repos[e.repos.length - 1]);
    if (e.cost === null || e.ts < since) continue;
    total += e.cost;
    // A message that touched several repositories splits its cost evenly among them.
    const targets = e.repos.length ? e.repos : [lastRepo.get(e.sid) ?? NO_FILE];
    for (const r of targets) credit(r, e.sid, e.cost / targets.length, 1 / targets.length);
  }
  const rows = [...acc.entries()].map(([repo, a]) => ({ repo, cost_usd: a.cost, records: a.records, sessions: a.sessions.size }))
    .sort((a, b) => b.cost_usd - a.cost_usd);
  return { rows, total_usd: total, files };
}
