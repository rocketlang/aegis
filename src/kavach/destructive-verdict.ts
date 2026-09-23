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
  | { kind: "match"; rule: DestructiveRule }
  | { kind: "clear" };

export function destructiveVerdict(command: string, rules: DestructiveRules): DestructiveVerdict {
  if (command.includes(rules.allowed_override_token)) return { kind: "override" };
  for (const rule of rules.bash_block_patterns) {
    if (new RegExp(rule.pattern, rule.flags).test(command)) return { kind: "match", rule };
  }
  return { kind: "clear" };
}
