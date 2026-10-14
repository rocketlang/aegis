// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// One SQLite opener for Bun and Node. (A copy of @xshieldai/aegis src/core/sqlite.ts: this package ships alone.)
//
// Under Bun this returns bun:sqlite's own Database, untouched: every Bun caller behaves exactly as
// before. Under Node (22.5+) it returns node:sqlite wrapped to the subset of the bun:sqlite API this
// repository uses (exec, run, query/prepare -> run/get/all, close), with Bun's binding and result
// conventions: an array of bindings is spread, true/false bind as 1/0, undefined binds as NULL, and
// get() with no row gives null. The driver is loaded when a database is opened, never at import, so
// a module that only imports this file loads under any Node.

import { createRequire } from "module";

export interface SqlStatement<T = any> {
  run(...params: unknown[]): { changes: number | bigint; lastInsertRowid: number | bigint };
  get(...params: unknown[]): T | null;
  all(...params: unknown[]): T[];
}

export interface SqlDb {
  exec(sql: string): void;
  run(sql: string, ...params: unknown[]): { changes: number | bigint; lastInsertRowid: number | bigint };
  query<T = any, _P = unknown>(sql: string): SqlStatement<T>;
  prepare<T = any, _P = unknown>(sql: string): SqlStatement<T>;
  close(): void;
}

export function isBun(): boolean {
  return Boolean((process.versions as Record<string, string | undefined>).bun);
}

export function openSqlite(path: string): SqlDb {
  const req = createRequire(import.meta.url);
  if (isBun()) {
    const { Database } = req("bun:sqlite");
    return new Database(path, { create: true }) as SqlDb;
  }
  let DatabaseSync: new (p: string) => NodeDb;
  try {
    ({ DatabaseSync } = req("node:sqlite"));
  } catch {
    throw new Error(`SQLite needs Bun or Node 22.5+ (node:sqlite); this is Node ${process.versions.node}.`);
  }
  return wrapNode(new DatabaseSync(path));
}

interface NodeStatement { run(...p: unknown[]): any; get(...p: unknown[]): any; all(...p: unknown[]): any[] }
interface NodeDb { exec(sql: string): void; prepare(sql: string): NodeStatement; close(): void }

// Bun accepts the bindings as one array or spread out; node:sqlite only spread out.
// node:sqlite refuses booleans and undefined, which bun:sqlite binds as 1/0 and NULL.
export function bindings(params: unknown[]): unknown[] {
  const list = params.length === 1 && Array.isArray(params[0]) ? (params[0] as unknown[]) : params;
  return list.map((v) => (v === undefined ? null : typeof v === "boolean" ? (v ? 1 : 0) : v));
}

function wrapStatement(s: NodeStatement): SqlStatement {
  return {
    run: (...p) => s.run(...bindings(p)),
    get: (...p) => s.get(...bindings(p)) ?? null,
    all: (...p) => s.all(...bindings(p)),
  };
}

function wrapNode(db: NodeDb): SqlDb {
  const cache = new Map<string, SqlStatement>();
  const query = (sql: string) => {
    let s = cache.get(sql);
    if (!s) {
      s = wrapStatement(db.prepare(sql));
      cache.set(sql, s);
    }
    return s;
  };
  return {
    exec: (sql) => db.exec(sql),
    run: (sql, ...p) => query(sql).run(...p),
    query,
    prepare: (sql) => wrapStatement(db.prepare(sql)),
    close: () => db.close(),
  };
}
