// SPDX-License-Identifier: AGPL-3.0-only
// The semantic gate's predicates, both outcomes forced. @rule:guards-assert-both-outcomes
import { describe, it, expect } from "bun:test";
import { isSqlCapableInvocation, isProvablyReadOnly, inlineStatement } from "../src/kavach/sql-capability";

describe("isSqlCapableInvocation", () => {
  it("recognises DB-client invocations, incl. quote-split and env-indirection", () => {
    for (const c of [
      "psql -c 'DROP TABLE t'",
      "psql -c 'DRO''P TABLE t'",       // quote-split — still a psql invocation
      "psql -c \"$LEGACY_SQL\"",         // env-indirection — still a psql invocation
      "echo 'DROP TABLE t' | psql",
      "mysql -e 'DELETE FROM x'",
      "prisma db execute --file drop.sql",
      "psql mydb",                        // interactive
    ]) expect(isSqlCapableInvocation(c)).toBe(true);
  });
  it("is false for non-DB-client commands", () => {
    for (const c of ["ls -la", "git status", "cat notes.md", "grep DROP file", "echo hi"])
      expect(isSqlCapableInvocation(c)).toBe(false);
  });
});

describe("isProvablyReadOnly", () => {
  it("proves the clear read cases", () => {
    for (const c of [
      "psql -c 'SELECT count(*) FROM ledger'",
      "psql -c 'EXPLAIN SELECT 1'",
      "psql -c '\\dt'",
      "psql -l",
      "psql --version",
    ]) expect(isProvablyReadOnly(c)).toBe(true);
  });
  it("refuses to prove writes, unknown shapes, and hidden statements", () => {
    for (const c of [
      "psql -c 'DROP TABLE t'",         // write verb
      "psql -c 'DRO''P TABLE t'",        // quote-split → extracted 'DRO' is not a read
      "psql -c \"$LEGACY_SQL\"",          // statement not in the string
      "psql -f migration.sql",           // file contents unknown
      "psql mydb",                        // interactive — could type anything
      "mysql -e 'UPDATE x SET y=1'",
    ]) expect(isProvablyReadOnly(c)).toBe(false);
  });
  it("extracts the inline statement only when the string reveals it", () => {
    expect(inlineStatement("psql -c 'SELECT 1'")).toBe("SELECT 1");
    expect(inlineStatement('psql -c "$SQL"')).toBe("$SQL");
    expect(inlineStatement("psql -f x.sql")).toBeNull();
  });

  it("AF-T-107: COPY … TO STDOUT is a read; FROM, TO PROGRAM, and a trailing write are not", () => {
    expect(isProvablyReadOnly("psql -c 'COPY ledger TO STDOUT'")).toBe(true);
    // a subquery COPY has FROM in it → conservatively NOT proven (safe: over-caution can't under-block)
    expect(isProvablyReadOnly("psql -c 'COPY (SELECT * FROM ledger) TO STDOUT'")).toBe(false);
    expect(isProvablyReadOnly("psql -c 'COPY ledger FROM STDIN'")).toBe(false);              // import
    expect(isProvablyReadOnly("psql -c 'COPY ledger TO PROGRAM rm'")).toBe(false);           // runs a shell
    expect(isProvablyReadOnly("psql -c 'COPY ledger TO STDOUT; DROP TABLE ledger'")).toBe(false); // hidden write
  });
});
