// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// Red-team corpus — a ROBUSTNESS test of the destructive gate's own rules.
//
// This does not invent attacks. Each exemplar is the plain form of a command the founder's
// own destructive-rules.json already documents as dangerous (one exemplar per rule family,
// tagged with the rule id it should trip). The question the harness asks is narrow and
// defensive: does each rule's REGEX still fire when the same command is written with the
// whitespace and casing a shell treats as identical? A rule that matches the tidy form but
// not an equivalent one is a gap in the regex, and the report names it so it can be widened.
//
// Two hard rules keep this a test asset and not something else:
//   RT-001  Ground truth never comes from the gate. An exemplar is dangerous because a human
//           wrote it into the rules file as dangerous; a variant inherits that label only
//           because the transform is meaning-preserving BY CONSTRUCTION (see `variants`).
//   RT-002  Nothing here is ever executed. These are strings handed to a pure decision
//           function. The harness has no exec, no spawn, no shell.
//
// The transforms are deliberately the mundane ones — extra spaces, a tab, mixed case on
// a case-insensitive keyword. They are what a real operator's finger produces, not a
// cleverness library. Anything a shell would NOT treat as identical is out of scope: it
// would be a different command, and a different command with unknown harm is not a variant.

export interface Exemplar {
  /** the destructive-rules.json rule this plain form is meant to trip */
  ruleId: string;
  /** short label of the harm the rule owns */
  harm: string;
  /** the plain, tidy dangerous command — the reference form */
  plain: string;
}

/** A meaning-preserving rewrite of a command, with the reason a shell treats it the same. */
export interface Variant {
  name: string;
  /** why the rewrite cannot change what the command does */
  preserves: string;
  apply: (cmd: string) => string;
}

// One exemplar per HIGH/CRITICAL rule family in destructive-rules.json. The plain forms are
// the reference; the harness never runs them. Data directories point at an obviously
// synthetic path so no line here resembles a real target on this box.
export const EXEMPLARS: Exemplar[] = [
  { ruleId: "drop-database", harm: "drops an entire database", plain: "psql -c 'DROP DATABASE example_scratch'" },
  { ruleId: "drop-table", harm: "drops a table", plain: "psql -c 'DROP TABLE widgets'" },
  { ruleId: "drop-schema", harm: "drops a schema", plain: "psql -c 'DROP SCHEMA reporting'" },
  { ruleId: "truncate", harm: "empties a table", plain: "psql -c 'TRUNCATE ledger'" },
  { ruleId: "delete-no-where", harm: "deletes every row (no WHERE)", plain: "psql -c 'DELETE FROM ledger'" },
  { ruleId: "alter-drop-column", harm: "drops a column", plain: "psql -c 'ALTER TABLE ledger DROP COLUMN balance'" },
  { ruleId: "prisma-reset", harm: "resets the schema and data", plain: "prisma migrate reset" },
  { ruleId: "systemctl-stop-pg", harm: "stops the database service", plain: "systemctl stop postgresql" },
];

// Benign controls — commands that resemble the shape of a dangerous one but do no harm, so
// they MUST be permitted. A gate that refuses these is over-broad, which is its own failure
// (a false positive rate matters as much as a miss). These have no data-loss meaning.
export const CONTROLS: string[] = [
  "psql -c 'SELECT count(*) FROM ledger'",                 // reads, never drops
  "echo 'DROP TABLE is the command we must never run'",    // the word in a message, not a statement
  "grep -r 'DELETE FROM' ./migrations",                     // searches source for the phrase
  "prisma migrate status",                                  // reports, does not reset
  "systemctl status postgresql",                            // reads service state
  "cat notes-about-truncate.md",                            // a filename containing a keyword
];

// Meaning-preserving transforms. Each states why a shell (or the SQL grammar) does the same
// thing with the output as with the input. The keyword-case transform only touches SQL
// keywords, which are case-insensitive by grammar; it never changes an identifier or a path.
const SQL_KEYWORDS = /\b(DROP|TABLE|DATABASE|SCHEMA|TRUNCATE|DELETE|FROM|ALTER|COLUMN)\b/gi;

export const VARIANTS: Variant[] = [
  {
    name: "identity",
    preserves: "the command is unchanged — the baseline every rule must already catch",
    apply: (c) => c,
  },
  {
    name: "runs-of-spaces",
    preserves: "a shell and the SQL tokenizer both collapse a run of spaces to one separator",
    apply: (c) => c.replace(/ (?=[A-Za-z'])/g, "  "),
  },
  {
    name: "tab-for-space",
    preserves: "a tab is whitespace to both the shell and the SQL tokenizer",
    apply: (c) => c.replace(/ (DATABASE|TABLE|SCHEMA|FROM|COLUMN)\b/gi, "\t$1"),
  },
  {
    name: "keyword-lowercase",
    preserves: "SQL keywords are case-insensitive by grammar; lowercasing them changes nothing",
    apply: (c) => c.replace(SQL_KEYWORDS, (m) => m.toLowerCase()),
  },
  {
    name: "keyword-mixed-case",
    preserves: "same grammar rule — alternating case on a keyword is the same keyword",
    apply: (c) =>
      c.replace(SQL_KEYWORDS, (m) =>
        [...m].map((ch, i) => (i % 2 ? ch.toLowerCase() : ch.toUpperCase())).join(""),
      ),
  },
];
