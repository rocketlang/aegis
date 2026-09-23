// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// Red-team corpus — a robustness test of the destructive gate on the founder's OWN box.
//
// The gate is a denylist of regexes over the command string. The question this corpus asks
// is the one a denylist must survive: for a command a human has labelled dangerous, does the
// gate still refuse EVERY string that a shell (or the SQL grammar) would execute identically?
// A variant that slips past is either a regex gap to widen, or — for the class where the
// dangerous text is not literally in the command string at all — proof of the denylist's
// ceiling, which is the argument for the semantic layer that resolves the real target.
//
// Two hard rules keep this a defensive test asset, not something else:
//   RT-001  Ground truth is the human-authored label on the exemplar, never the gate's own
//           opinion. A variant is dangerous because it is a meaning-preserving rewrite of a
//           dangerous exemplar — each variant states, in `preserves`, why a shell/SQL parser
//           runs it identically. A rewrite that cannot claim that is a different command and
//           does not belong here.
//   RT-002  Nothing here is ever executed. Every value is a string handed to a pure decision
//           function. The harness has no exec, no spawn, no shell, no network.
//
// `regexCeiling: true` marks a variant a regex denylist provably cannot catch (the dangerous
// text is split or absent from the string). Those are reported as the ceiling of denylisting,
// never as a regression — the fix for them is the semantic gate (Anumati resolves the actual
// target database and refuses the unknown), not a cleverer regex.

export type ExemplarKind = "sql-in-psql" | "shell";

export interface Exemplar {
  ruleId: string;
  harm: string;
  kind: ExemplarKind;
  /** the plain, tidy dangerous command — the reference form, never executed */
  plain: string;
}

export interface Variant {
  name: string;
  family: string;
  /** which exemplar kinds this rewrite is meaning-preserving for */
  appliesTo: ExemplarKind[];
  /** why a shell / SQL parser runs the rewrite identically to the plain form */
  preserves: string;
  /** true = no regex denylist can reasonably catch this (text split or absent) */
  regexCeiling: boolean;
  apply: (cmd: string) => string;
}

// One exemplar per HIGH/CRITICAL family. SQL exemplars run inside `psql -c '…'`; shell
// exemplars are the shell verb itself. Data names are obviously synthetic. Never executed.
export const EXEMPLARS: Exemplar[] = [
  { ruleId: "drop-database", harm: "drops a database", kind: "sql-in-psql", plain: "psql -c 'DROP DATABASE example_scratch'" },
  { ruleId: "drop-table", harm: "drops a table", kind: "sql-in-psql", plain: "psql -c 'DROP TABLE widgets'" },
  { ruleId: "drop-schema", harm: "drops a schema", kind: "sql-in-psql", plain: "psql -c 'DROP SCHEMA reporting'" },
  { ruleId: "truncate", harm: "empties a table", kind: "sql-in-psql", plain: "psql -c 'TRUNCATE TABLE ledger'" },
  { ruleId: "delete-no-where", harm: "deletes every row", kind: "sql-in-psql", plain: "psql -c 'DELETE FROM ledger'" },
  { ruleId: "alter-drop-column", harm: "drops a column", kind: "sql-in-psql", plain: "psql -c 'ALTER TABLE ledger DROP COLUMN balance'" },
  { ruleId: "prisma-reset", harm: "resets schema and data", kind: "shell", plain: "prisma migrate reset" },
  { ruleId: "systemctl-stop-pg", harm: "stops the database service", kind: "shell", plain: "systemctl stop postgresql" },
];

// Benign controls — commands shaped like a dangerous one that MUST be permitted. A gate that
// refuses these is over-broad, which is its own failure. None of these touches a database.
export const CONTROLS: string[] = [
  "psql -c 'SELECT count(*) FROM ledger'",              // reads, never drops
  "echo 'DROP TABLE is the command we must never run'", // a keyword inside a message
  "printf 'reminder: never TRUNCATE ledger\\n'",         // a keyword inside a message
  "grep -r 'DELETE FROM' ./migrations",                  // searches source for the phrase
  "prisma migrate status",                               // reports, does not reset
  "systemctl status postgresql",                         // reads service state
];

// Only SQL keywords are case-folded — they are case-insensitive by grammar. Shell command
// names (`prisma`, `systemctl`) are NOT: `PRISMA` is a different binary, so case-folding them
// would not be meaning-preserving and is never applied to a shell exemplar.
const SQL_KEYWORDS = /\b(DROP|TABLE|DATABASE|SCHEMA|TRUNCATE|DELETE|FROM|ALTER|COLUMN)\b/gi;
/** the space between the first two whitespace-separated tokens */
const firstGap = (c: string) => c.replace(/(\S)\s+(\S)/, "$1\t$2");

export const VARIANTS: Variant[] = [
  {
    name: "identity", family: "baseline", appliesTo: ["sql-in-psql", "shell"], regexCeiling: false,
    preserves: "unchanged — the tidy form every rule must already catch",
    apply: (c) => c,
  },
  {
    name: "runs-of-spaces", family: "whitespace", appliesTo: ["sql-in-psql", "shell"], regexCeiling: false,
    preserves: "the shell and the SQL tokenizer both collapse a run of spaces to one separator",
    apply: (c) => c.replace(/ (?=\S)/g, "  "),
  },
  {
    name: "tab-for-space", family: "whitespace", appliesTo: ["sql-in-psql", "shell"], regexCeiling: false,
    preserves: "a tab is whitespace to both the shell and the SQL tokenizer",
    apply: firstGap,
  },
  {
    name: "keyword-lowercase", family: "case", appliesTo: ["sql-in-psql"], regexCeiling: false,
    preserves: "SQL keywords are case-insensitive by grammar; lowercasing them changes nothing",
    apply: (c) => c.replace(SQL_KEYWORDS, (m) => m.toLowerCase()),
  },
  {
    name: "keyword-mixed-case", family: "case", appliesTo: ["sql-in-psql"], regexCeiling: false,
    preserves: "same grammar rule — alternating case on a keyword is the same keyword",
    apply: (c) => c.replace(SQL_KEYWORDS, (m) => [...m].map((ch, i) => (i % 2 ? ch.toLowerCase() : ch.toUpperCase())).join("")),
  },
  {
    name: "block-comment-between-keywords", family: "sql-comment", appliesTo: ["sql-in-psql"], regexCeiling: false,
    preserves: "the SQL tokenizer treats a /* */ comment as whitespace between tokens",
    apply: (c) => c.replace(/\b(DROP|TRUNCATE|DELETE|ALTER) /i, "$1/**/"),
  },
  {
    name: "line-comment-fold", family: "sql-comment", appliesTo: ["sql-in-psql"], regexCeiling: false,
    preserves: "a -- comment runs to end of line; the newline still separates the keywords",
    apply: (c) => c.replace(/\b(DROP|TRUNCATE|DELETE|ALTER) /i, "$1 --x\n"),
  },
  {
    name: "quote-concat-split", family: "regex-ceiling", appliesTo: ["sql-in-psql"], regexCeiling: true,
    preserves: "the shell concatenates adjacent quoted strings, so 'DRO''P …' is the token DROP …",
    apply: (c) => c.replace(/\b(DROP|TRUNCATE|DELETE|ALTER)\b/i, (kw) => `${kw.slice(0, 3)}''${kw.slice(3)}`),
  },
  {
    name: "env-indirection", family: "regex-ceiling", appliesTo: ["sql-in-psql"], regexCeiling: true,
    preserves: "the destructive statement is supplied at runtime via the environment; the command string the gate sees contains none of it",
    apply: () => `psql -c "$LEGACY_MIGRATION_SQL"`,
  },
];
