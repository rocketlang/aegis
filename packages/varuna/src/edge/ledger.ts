/**
 * Edge ledger — the Varuna Box's offline-first memory (Vivechana A, edge agent).
 * @rule:VRN-EDGE-001 Append-only, on-disk — survives power cycle / reboot at sea
 * @rule:VRN-EDGE-002 Offline-first — posture buffers locally when dark, syncs on connect
 *
 * A ship goes dark mid-ocean; the runaway-diesel attack happens THERE. So every posture
 * snapshot is appended to an on-disk JSONL ledger (not RAM), and flushed to shore only
 * when connectivity returns. Append-only: records are never mutated; sync progress is a
 * separate high-water-mark, so the evidence trail is tamper-evident by construction.
 */

import { existsSync, mkdirSync, appendFileSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

const DATA_DIR = process.env['VARUNA_EDGE_DIR'] ?? path.resolve('data');
const LEDGER = path.join(DATA_DIR, 'edge-ledger.jsonl');
const HWM = path.join(DATA_DIR, 'edge-ledger.synced'); // last-synced seq (sync progress, not data)

export interface EdgeRecord {
  seq: number;
  ts: string;
  vessel_id: string;
  posture_score: number | null;
  posture_band: string;
  kind: string; // 'posture' | 'degradation' | 'compliance' | …
}

function ensureDir(): void {
  if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });
}

function nextSeq(): number {
  return readAll().length + 1;
}

/** Append a record — the only write path. On-disk, survives reboot. */
export function appendEdge(rec: Omit<EdgeRecord, 'seq' | 'ts'>): EdgeRecord {
  ensureDir();
  const full: EdgeRecord = { seq: nextSeq(), ts: new Date().toISOString(), ...rec };
  appendFileSync(LEDGER, JSON.stringify(full) + '\n');
  return full;
}

export function readAll(): EdgeRecord[] {
  try {
    return readFileSync(LEDGER, 'utf8')
      .split('\n')
      .filter(Boolean)
      .map((l) => JSON.parse(l) as EdgeRecord);
  } catch {
    return [];
  }
}

function highWaterMark(): number {
  try {
    return parseInt(readFileSync(HWM, 'utf8').trim(), 10) || 0;
  } catch {
    return 0;
  }
}

/** Records not yet flushed to shore (seq > high-water-mark). */
export function unsynced(): EdgeRecord[] {
  const hwm = highWaterMark();
  return readAll().filter((r) => r.seq > hwm);
}

/** Advance the sync high-water-mark after a successful shore flush (append-only preserved). */
export function markSynced(upToSeq: number): void {
  ensureDir();
  writeFileSync(HWM, String(upToSeq));
}

export function edgeStats(): { total: number; unsynced: number; lastSyncedSeq: number } {
  const all = readAll();
  return { total: all.length, unsynced: unsynced().length, lastSyncedSeq: highWaterMark() };
}

/**
 * Sync-on-connect: flush unsynced records to shore. Returns what happened. If shore is
 * unreachable (mid-ocean), it is a no-op — records stay buffered for the next window.
 */
export async function syncOnConnect(
  shoreUrl: string | null
): Promise<{ flushed: number; reachable: boolean }> {
  const pending = unsynced();
  if (pending.length === 0) return { flushed: 0, reachable: true };
  if (!shoreUrl) return { flushed: 0, reachable: false };
  try {
    const res = await fetch(shoreUrl.replace(/\/$/, '') + '/api/edge/ingest', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ records: pending }),
    });
    if (!res.ok) return { flushed: 0, reachable: false };
    markSynced(pending[pending.length - 1]!.seq);
    return { flushed: pending.length, reachable: true };
  } catch {
    return { flushed: 0, reachable: false }; // dark — keep buffering
  }
}
