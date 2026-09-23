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

export interface DestructiveRule {
  pattern: string;
  flags: string;
  reason: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM";
}

export interface DestructiveRules {
  bash_block_patterns: DestructiveRule[];
  allowed_override_token: string;
}

export type DestructiveVerdict =
  | { kind: "override" }
  | { kind: "match"; rule: DestructiveRule; via: "raw" | "normalized" }
  | { kind: "inert"; wouldMatch: DestructiveRule } // a keyword only DISPLAYED, never executed
  | { kind: "clear" };

// Shell metacharacters that could turn a display command into an executing one: a pipe,
// a redirect, a chain, a command substitution, or a newline that starts a new command.
// If a command carries ANY of these, it is NOT treated as an inert display — it is judged
// on its content like anything else. This is the whole safety of the inert carve-out.
const EXECUTION_METACHAR = /[|&;<>`\n]|\$\(/;

/**
 * A command whose destructive keyword can only be DISPLAYED, never reach an interpreter:
 * a bare `echo`/`printf` of a string, or a shell comment, with no execution path at all.
 * `echo 'DROP TABLE t'` prints text; `echo 'DROP TABLE t' | psql` does not qualify (the pipe
 * is an execution path) and is judged normally. Deliberately narrow: it suppresses only the
 * most trivial false positive and can never wave a real destructive command through, because
 * reaching a database always needs one of the excluded metacharacters. @rule:KAV-052
 */
export function isInertDisplay(command: string): boolean {
  const c = command.trim();
  if (c.startsWith("#")) return true; // a shell comment executes nothing
  if (!/^(echo|printf)\b/.test(c)) return false;
  return !EXECUTION_METACHAR.test(c);
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

function firstMatch(text: string, rules: DestructiveRules): DestructiveRule | null {
  for (const rule of rules.bash_block_patterns) {
    if (new RegExp(rule.pattern, rule.flags).test(text)) return rule;
  }
  return null;
}

export function destructiveVerdict(command: string, rules: DestructiveRules): DestructiveVerdict {
  if (command.includes(rules.allowed_override_token)) return { kind: "override" };

  const raw = firstMatch(command, rules);
  if (raw) {
    // The keyword is present, but only as displayed text with no way to execute → not destructive.
    if (isInertDisplay(command)) return { kind: "inert", wouldMatch: raw };
    return { kind: "match", rule: raw, via: "raw" };
  }
  // Union: a comment- or whitespace-obfuscated variant the raw pattern missed.
  const norm = firstMatch(normalizeForMatch(command), rules);
  if (norm) {
    if (isInertDisplay(command)) return { kind: "inert", wouldMatch: norm };
    return { kind: "match", rule: norm, via: "normalized" };
  }
  return { kind: "clear" };
}
