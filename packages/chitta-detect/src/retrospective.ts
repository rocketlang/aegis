// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// @rule:INF-CG-005 — no scan receipt for post-deployment content → mark for retrospective audit
// @rule:CG-007 — every memory write generates a PRAMANA receipt

const DEPLOYMENT_TIMESTAMP = process.env.CHITTA_GUARD_DEPLOYMENT_TS
  ? new Date(process.env.CHITTA_GUARD_DEPLOYMENT_TS)
  : new Date('2026-05-09T00:00:00.000Z');

export type AuditStatus = 'RECEIPT_PRESENT' | 'RECEIPT_MISSING' | 'PRE_DEPLOYMENT';

export interface ChunkAuditRecord {
  content_hash: string;
  write_timestamp: Date;
  audit_status: AuditStatus;
  queued_for_retrospective_scan: boolean;
  agent_id: string;
}

const _auditQueue: ChunkAuditRecord[] = [];
const _knownReceiptHashes = new Set<string>();

export function registerReceipt(contentHash: string): void {
  _knownReceiptHashes.has(contentHash) || _knownReceiptHashes.add(contentHash);
}

export function audit(
  contentHash: string,
  writeTimestamp: Date,
  agentId: string
): ChunkAuditRecord {
  const isPreDeployment = writeTimestamp < DEPLOYMENT_TIMESTAMP;
  const hasReceiptForHash = _knownReceiptHashes.has(contentHash);

  const status: AuditStatus = isPreDeployment
    ? 'PRE_DEPLOYMENT'
    : hasReceiptForHash
    ? 'RECEIPT_PRESENT'
    : 'RECEIPT_MISSING';

  const record: ChunkAuditRecord = {
    content_hash: contentHash,
    write_timestamp: writeTimestamp,
    audit_status: status,
    queued_for_retrospective_scan: status === 'RECEIPT_MISSING',
    agent_id: agentId,
  };

  if (status === 'RECEIPT_MISSING') {
    _auditQueue.push(record);
  }

  return record;
}

export function getQueue(): ChunkAuditRecord[] {
  return [..._auditQueue];
}

export function getQueueDepth(): number {
  return _auditQueue.length;
}

export function getDeploymentTimestamp(): Date {
  return DEPLOYMENT_TIMESTAMP;
}

export function hasReceipt(contentHash: string): boolean {
  return _knownReceiptHashes.has(contentHash);
}
