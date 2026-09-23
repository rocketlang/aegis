// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// The semantic gate's two predicates (AF-T-101 / AF-T-102). They ask about the INVOCATION,
// not the SQL text — which is exactly why they see through the regex-ceiling evasions the
// lexical denylist cannot: a quote-split keyword (`'DRO''P TABLE'`) or a statement supplied
// from the environment (`psql -c "$SQL"`) is still an arbitrary-SQL invocation, and still
// not provably read-only. Pure functions, no side effects, never execute anything.
//
// The discipline is FP-018's: PROVE a statement is read-only, or treat it as a write. And
// "the statement" is EVERY statement source the invocation carries — a client runs all of
// its -c/-e statements in order, so one benign leading statement can never vouch for a later
// one (the multi-`-c` gap, AF-T-109). When any statement source cannot be read (a -f file, a
// heredoc, a stdin pipe, a $VAR), read-only is not provable, and the caller treats it as a
// write and judges it on the resolved target's class.

/** DB clients that run arbitrary SQL/commands. Substring-anchored, so `docker exec … psql`
 *  and `kubectl exec … mysql` are covered too. `prisma db execute` runs a script file. */
const SQL_CLIENT = /\b(psql|mysql|mariadb|mongosh|mongo|pgcli|mycli|usql|sqlite3|cockroach\s+sql|clickhouse-client)\b/i;

/**
 * Does this command invoke something that can execute arbitrary SQL against a database?
 * A property of the invoker, so quote-splitting or env-indirection in the statement cannot
 * hide it. Widen the client set (AF-R-003) as more appear on the box.
 */
export function isSqlCapableInvocation(command: string): boolean {
  if (/\bprisma\s+db\s+execute\b/i.test(command)) return true;
  return SQL_CLIENT.test(command);
}

/** EVERY inline statement the command carries via -c/--command/-e/--eval/--execute, in order.
 *  A client runs all of them, so read-only must hold for all of them (AF-T-109). */
export function inlineStatements(command: string): string[] {
  const re = /(?:^|\s)(?:-c|--command|-e|--eval|--execute)(?:=|\s+)('([^']*)'|"([^"]*)"|(\S+))/gi;
  const out: string[] = [];
  for (const m of command.matchAll(re)) out.push(m[2] ?? m[3] ?? m[4] ?? "");
  return out;
}

/** The FIRST inline statement, or null. Kept for callers that want just one; the read-only
 *  decision uses inlineStatements (all of them). */
export function inlineStatement(command: string): string | null {
  return inlineStatements(command)[0] ?? null;
}

/**
 * A statement source the command string cannot reveal, so its contents are unknown: a script
 * file (`-f`/`--file`), a heredoc (`<<`), or a pipe feeding the client its statements on stdin.
 * Any of these means read-only cannot be proven.
 */
export function hasHiddenStatementSource(command: string): boolean {
  if (/(?:^|\s)(?:-f|--file)\b/i.test(command)) return true;
  if (/<<-?\s*['"]?\w/.test(command)) return true; // heredoc
  if (/\|\s*(?:sudo\s+\S+\s+)?(?:psql|mysql|mariadb|mongosh|mongo|pgcli|mycli|usql|sqlite3|clickhouse-client)\b/i.test(command)) return true; // stdin pipe into a client
  return false;
}

const WRITE_VERB = /\b(INSERT|UPDATE|DELETE|DROP|TRUNCATE|ALTER|CREATE|GRANT|REVOKE|REPLACE|MERGE|CALL|DO|COPY|VACUUM|REINDEX|CLUSTER|COMMENT|REFRESH|SET|LOCK)\b/i;
const READ_START = /^\s*(SELECT|EXPLAIN|SHOW|WITH\b|VALUES\b)/i;
const READ_META = /^\s*\\(dt|d|l|dn|df|dv|z|conninfo|list|encoding)\b/i;

/** Is ONE statement unambiguously a read? A write verb fails unless it is the lone
 *  `COPY … TO STDOUT` export exception. An unrecognised shape fails (treat as a write). */
function isReadOnlyStatement(stmt: string): boolean {
  const s = stmt.trim();
  if (s === "") return false;
  if (READ_META.test(s)) return true;
  if (WRITE_VERB.test(s)) {
    // AF-T-107 — the one write-verb exception: `COPY … TO STDOUT` exports rows, it does not
    // mutate the database. Allowed ONLY when COPY is the sole write verb (so `COPY x TO STDOUT;
    // DROP TABLE y` is still a write), with no FROM (an import) and no TO PROGRAM (runs a shell).
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

/**
 * Can we PROVE this invocation only reads? Yes only when EVERY statement it carries is present
 * in the command string AND is unambiguously a read (or it is a --version/--list that runs no
 * statement). A single write among many, an unreadable statement source (-f/heredoc/pipe), an
 * unrecognised statement, or a hidden statement ($VAR, interactive) all make it NOT provable —
 * and the caller then treats it as a write. @rule:AFW-YK-001
 */
export function isProvablyReadOnly(command: string): boolean {
  // Flags that connect but run no statement, or don't connect at all.
  if (
    /(?:^|\s)(?:-V|--version|-l|--list|-\?|--help)\b/i.test(command) &&
    !/(?:-c|--command|-e|--eval|--execute|-f|--file)\b/i.test(command)
  ) {
    return true;
  }
  // A statement source we cannot read means we cannot prove read-only.
  if (hasHiddenStatementSource(command)) return false;
  const stmts = inlineStatements(command);
  if (stmts.length === 0) return false; // interactive session or a hidden statement
  // Every statement the client will run must be a read — one write anywhere fails the whole.
  return stmts.every(isReadOnlyStatement);
}
