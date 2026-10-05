// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// The Level-2 decision of check-destructive, as a pure function of (command, rules).
//
// Split out so the hook and the red-team harness judge a command with the SAME code. The
// hook adds the side effects (the KAVACH approval gate, WhatsApp, stderr); this file has
// none, and must keep having none — the harness evaluates thousands of attack strings
// through it, and a side effect here would page a human once per string.
// @rule:KAV-052
// @rule:KAV-098 — nothing typed into the command overrides the gate. Before 2.5.0 a fixed
//                 token in the command text did; the token was in the public source and the
//                 gate printed it to the agent it had just refused. An override is now a
//                 one-time approval a person gives for one exact command
//                 (destructive-approval.ts), and this file knows nothing about it.
// @rule:KAV-099 — removing the root or the home directory is recognised from the command's
//                 structure, not from one spelling of its flags.

import { parseCommand } from "../shield/bash-scan";

export interface DestructiveRule {
  pattern: string;
  flags: string;
  reason: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM";
}

export interface DestructiveRules {
  bash_block_patterns: DestructiveRule[];
  /** Ignored since 2.5.0 (KAV-098). Kept in the type so older rules files still load. */
  allowed_override_token?: string;
}

export type DestructiveVerdict =
  | { kind: "match"; rule: DestructiveRule; via: "raw" | "normalized" | "built-in" }
  | { kind: "inert"; wouldMatch: DestructiveRule } // a keyword only DISPLAYED, never executed
  | { kind: "clear" };

// Shell metacharacters that could turn a display command into an executing one: a pipe,
// a redirect, a chain, a command substitution, or a newline that starts a new command.
// If a command carries ANY of these, it is NOT treated as an inert display — it is judged
// on its content like anything else. This is the whole safety of the inert carve-out.
const EXECUTION_METACHAR = /[|&;<>`\n]|\$\(/;

// Programs that only show or record the text they are given, and have NO option that runs
// another program: echo, printf, GNU grep, and a commit or tag message. The list is short
// on purpose. ripgrep (--pre), ag (--pager), `git grep` (-O) and `git log`/`git show`
// (external diff and pager settings) can each be told to run a program, so they are not
// on it: a destructive phrase in their arguments is judged like any other.
const DISPLAY_ONLY = /^(?:echo|printf|grep|egrep|fgrep|git\s+(?:commit|tag))\b/;

/**
 * A command whose destructive keyword can only be DISPLAYED, never reach an interpreter:
 * a bare `echo`/`printf` of a string, a `grep` for it, a commit or tag message that
 * mentions it — with no execution path at all — or text that is comment lines and nothing
 * else. `echo 'DROP TABLE t'` prints text; `echo 'DROP TABLE t' | psql` does not qualify
 * (the pipe is an execution path) and is judged normally.
 *
 * A comment is inert only when EVERY line is a comment. Before 2.5.0 a command was inert as
 * soon as it began with "#", so a comment on the first line let any second line through.
 * @rule:KAV-052
 */
export function isInertDisplay(command: string): boolean {
  const c = command.trim();
  if (c.length === 0) return true;
  const lines = c.split("\n").map((l) => l.trim()).filter((l) => l.length > 0);
  if (lines.every((l) => l.startsWith("#"))) return true; // comments execute nothing
  if (EXECUTION_METACHAR.test(c)) return false;
  return DISPLAY_ONLY.test(c);
}

/**
 * A view of the command for ADDITIONAL matching only. It strips SQL comments (block and
 * line-to-end comments, each replaced by a space so tokens don't fuse) and collapses runs of
 * whitespace. It is unioned with the raw match, never used alone: normalization can only ADD
 * a match, so it closes evasions (a comment or odd spacing wedged between keywords) and can
 * never remove a block the raw text would have caught — it cannot create a bypass.
 */
export function normalizeForMatch(command: string): string {
  return command
    .replace(/\/\*[\s\S]*?\*\//g, " ") // /* block comment */
    .replace(/--[^\n]*/g, " ")          // -- line comment to end of line
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * A second additional view: the command as the shell joins it. Quote characters and
 * backslashes are removed, so a keyword with quotes spliced into it (the two halves of a
 * word either side of an empty pair of quotes) reads as the keyword. Unioned, like the
 * view above.
 */
export function dequoteForMatch(command: string): string {
  return normalizeForMatch(command.replace(/["'\\]/g, ""));
}

const compiled = new Map<string, RegExp | null>();
function compile(rule: DestructiveRule): RegExp | null {
  const key = `${rule.flags}\u0000${rule.pattern}`;
  let re = compiled.get(key);
  if (re === undefined) {
    try { re = new RegExp(rule.pattern, String(rule.flags ?? "").replace(/[gy]/g, "")); } catch { re = null; }
    compiled.set(key, re);
  }
  return re;
}

function firstMatch(text: string, rules: DestructiveRules): DestructiveRule | null {
  for (const rule of rules.bash_block_patterns) {
    const re = compile(rule); // a pattern that does not compile is skipped
    if (re && re.test(text)) return rule;
  }
  return null;
}

// A shell command of this size cannot be judged in the time a hook has. Not knowing refuses.
const MAX_COMMAND = 512_000;
const TOO_LONG: DestructiveRule = { pattern: "(built-in) command too long to judge", flags: "", reason: `The command is longer than ${MAX_COMMAND} characters — too long for this gate to judge in time, so it is refused`, severity: "HIGH" };
const RM_ROOT: DestructiveRule = { pattern: "(built-in) recursive rm of / or the home directory", flags: "", reason: "Recursive removal of the root or the home directory — catastrophic filesystem wipe", severity: "CRITICAL" };

/** `/`, `/*`, `~`, `~/*`, `$HOME`, `${HOME}/` … as a removal target. */
function isRootOrHome(target: string): boolean {
  const t = target.replace(/\/\*$/, "").replace(/\/+$/, "");
  return t === "" || t === "~" || t === "$HOME" || t === "${HOME}" || t === "/.";
}

/**
 * KAV-099 — what the patterns cannot see reliably: a recursive `rm` whose target is the
 * root or the home directory, however its flags are written (`-rf`, `-r -f`, `-fR`,
 * `--recursive --force`, with `--no-preserve-root`, after `sudo`, inside `bash -c`).
 */
export function structuralMatch(command: string): DestructiveRule | null {
  for (const c of parseCommand(command)) {
    if (c.verb !== "rm") continue;
    const recursive = c.args.some((a) => a === "--recursive" || (/^-[A-Za-z]+$/.test(a) && /[rR]/.test(a)));
    if (!recursive) continue;
    if (c.args.some((a) => !a.startsWith("-") && isRootOrHome(a))) return RM_ROOT;
  }
  return null;
}

export function destructiveVerdict(command: string, rules: DestructiveRules): DestructiveVerdict {
  if (typeof command !== "string" || command.length === 0) return { kind: "clear" };
  if (command.length > MAX_COMMAND) return { kind: "match", rule: TOO_LONG, via: "built-in" };

  const raw = firstMatch(command, rules);
  if (raw) {
    // The keyword is present, but only as displayed text with no way to execute → not destructive.
    if (isInertDisplay(command)) return { kind: "inert", wouldMatch: raw };
    return { kind: "match", rule: raw, via: "raw" };
  }
  // Union: a comment-, whitespace- or quote-obfuscated variant the raw pattern missed.
  const norm = firstMatch(normalizeForMatch(command), rules) ?? firstMatch(dequoteForMatch(command), rules);
  if (norm) {
    if (isInertDisplay(command)) return { kind: "inert", wouldMatch: norm };
    return { kind: "match", rule: norm, via: "normalized" };
  }
  const built = structuralMatch(command);
  if (built) return { kind: "match", rule: built, via: "built-in" };
  return { kind: "clear" };
}
