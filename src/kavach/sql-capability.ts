// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// The semantic gate's two predicates (AF-T-101 / AF-T-102). They ask about the INVOCATION,
// not the SQL text — which is exactly why they see through the regex-ceiling evasions the
// lexical denylist cannot: a quote-split keyword (`'DRO''P TABLE'`) or a statement supplied
// from the environment (`psql -c "$SQL"`) is still an arbitrary-SQL invocation, and still
// not provably read-only. Pure functions, no side effects, never execute anything.
//
// The discipline is FP-018's: PROVE a statement is read-only, or treat it as a write. When
// the statement is not in the command string (a variable, a file, a heredoc, an interactive
// session), it cannot be proven read-only, so it is treated as capable of writing — and the
// permissive that uses these will then judge it on the resolved target's class.

/** DB clients that run arbitrary SQL/commands. `prisma db execute` runs a script too. */
const SQL_CLIENT = /\b(psql|mysql|mariadb|mongosh|mongo)\b/i;

/**
 * Does this command invoke something that can execute arbitrary SQL against a database?
 * A property of the invoker, so quote-splitting or env-indirection in the statement cannot
 * hide it. Conservative on the client set — widen (AF-T-101) as more clients appear on the box.
 */
export function isSqlCapableInvocation(command: string): boolean {
  if (/\bprisma\s+db\s+execute\b/i.test(command)) return true;
  return SQL_CLIENT.test(command);
}

/** The inline statement of a `-c`/`--command`/`-e`/`--eval` flag, or null if there isn't one
 *  the string can reveal (a $VAR, a -f file, a heredoc, or an interactive session all give null). */
export function inlineStatement(command: string): string | null {
  const m = /(?:^|\s)(?:-c|--command|-e|--eval)(?:=|\s+)('([^']*)'|"([^"]*)"|(\S+))/i.exec(command);
  if (!m) return null;
  return m[2] ?? m[3] ?? m[4] ?? null;
}

const WRITE_VERB = /\b(INSERT|UPDATE|DELETE|DROP|TRUNCATE|ALTER|CREATE|GRANT|REVOKE|REPLACE|MERGE|CALL|DO|COPY|VACUUM|REINDEX|CLUSTER|COMMENT|REFRESH|SET|LOCK)\b/i;
const READ_START = /^\s*(SELECT|EXPLAIN|SHOW|WITH\b|VALUES\b)/i;
const READ_META = /^\s*\\(dt|d|l|dn|df|dv|z|conninfo|list|encoding)\b/i;

/**
 * Can we PROVE this invocation only reads? Only when the statement is present in the command
 * AND is unambiguously a read (a SELECT/EXPLAIN/SHOW, a read-only psql meta-command, or a
 * --version/--list that never runs a statement). Everything else — a write verb, an
 * unrecognised statement, or a statement the string does not contain — is NOT provable, and
 * the caller must treat it as a potential write.
 */
export function isProvablyReadOnly(command: string): boolean {
  // Flags that connect but run no statement, or don't connect at all.
  if (/(?:^|\s)(?:-V|--version|-l|--list|-\?|--help)\b/i.test(command) && !/(?:-c|--command|-f|--file)\b/i.test(command)) {
    return true;
  }
  const stmt = inlineStatement(command);
  if (stmt === null) return false; // $VAR, -f file, heredoc, interactive → cannot prove
  const s = stmt.trim();
  if (READ_META.test(s)) return true;
  if (WRITE_VERB.test(s)) {
    // AF-T-107 — the one write-verb exception: `COPY … TO STDOUT` exports rows, it does not
    // mutate the database. Allowed ONLY when COPY is the sole write verb (so `COPY x TO STDOUT;
    // DROP TABLE y` is still a write) and there is no FROM (an import) and no TO PROGRAM (runs a
    // shell). Cannot under-block a mutation: a pure export changes no data. @rule:AFW-YK-001
    const isCopyToStdout =
      /^\s*COPY\b[\s\S]*\bTO\s+STDOUT\b/i.test(s) &&
      !/\bFROM\b/i.test(s) &&
      !/\bTO\s+PROGRAM\b/i.test(s);
    const otherWriteVerb = WRITE_VERB.test(s.replace(/\bCOPY\b/gi, " "));
    if (isCopyToStdout && !otherWriteVerb) return true;
    return false;
  }
  if (READ_START.test(s)) return true;
  return false; // unrecognised statement shape → not provable → treat as write
}
