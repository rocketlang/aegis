// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.

// @xshieldai/aegis-suite — the event store opens on the runtime it finds (v0.4.0)
// Under Bun it is bun:sqlite; under Node 22.5+ it is node:sqlite. Until 0.4.0 the module imported
// bun:sqlite at the top, so plain Node could not import the package at all.

import { describe, it, expect } from 'bun:test';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { SqliteEventWriter, createDefaultBus, openSqlite } from '../src/bus.js';

const receipt = (i: number) => ({ receipt_id: `r-${i}`, primitive: 'test', event_type: 'test.event', emitted_at: new Date().toISOString(), verdict: 'PASS', payload: { i } });

describe('event store', () => {
  it('BUS-001 a writer saves receipts and counts them', () => {
    const w = new SqliteEventWriter({ path: join(mkdtempSync(join(tmpdir(), 'suite-')), 'acc.db') });
    w.write(receipt(1)); w.write(receipt(2));
    expect(w.totalCount()).toBe(2);
    w.close();
  });
  it('BUS-002 the default bus fans out to subscribers and to the store', () => {
    const { bus, writer } = createDefaultBus({ sqlitePath: join(mkdtempSync(join(tmpdir(), 'suite-')), 'acc.db') });
    const seen: string[] = [];
    bus.subscribe((r) => seen.push(r.receipt_id));
    bus.emit(receipt(3));
    expect(seen).toEqual(['r-3']);
    expect(writer!.totalCount()).toBe(1);
    writer!.close();
  });
  it('BUS-003 persist:false opens no store at all', () => {
    expect(createDefaultBus({ persist: false }).writer).toBeNull();
  });
  it('BUS-004 openSqlite gives the four calls the writer uses', () => {
    const db = openSqlite(join(mkdtempSync(join(tmpdir(), 'suite-')), 'x.db'));
    db.exec('CREATE TABLE t (n INTEGER)');
    db.query('INSERT INTO t VALUES (?)').run(7);
    expect((db.query('SELECT n FROM t').get() as { n: number }).n).toBe(7);
    db.close();
  });
});
