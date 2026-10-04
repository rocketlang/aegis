#!/usr/bin/env bun
// @xshieldai/aegis-guard — runnable quickstart
//
// What you'll see: 5 Locks primitives in action, each emitting a receipt.
// Run: bun run packages/aegis-guard/examples/quickstart.ts

import {
  setEventBus,
  verifyApprovalToken,
  mintApprovalToken,
  ensureSigningKeypair,
  checkIdempotency,
  buildIdempotencyFingerprint,
  emitAegisSenseEvent,
  configureSenseTransport,
  digestApprovalToken,
  verifyAndConsumeNonce,
  defaultNonceStore,
  type AccReceipt,
} from '../src/index.js';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// 0) The quickstart plays the approving authority, so it needs a signing key. It makes a
//    throwaway one in a temp directory and leaves your ~/.aegis alone. In a real
//    deployment only the AEGIS box calls ensureSigningKeypair(); every other service is
//    given the public key and can verify, not mint.
process.env.AEGIS_DIR = mkdtempSync(join(tmpdir(), 'aegis-guard-quickstart-'));
delete process.env.AEGIS_APPROVAL_PUBKEY_PEM;
ensureSigningKeypair();

// 1) Wire the ACC bus so every receipt prints to stdout
setEventBus({
  emit: (r: AccReceipt) =>
    console.log(`📜 ${r.event_type.padEnd(28)} verdict=${(r.verdict ?? '').padEnd(4)} ${r.summary ?? ''}`),
});

// SENSE events also surface
configureSenseTransport((ev) =>
  console.log(`👁  SENSE  ${ev.event_type.padEnd(28)} irreversible=${ev.irreversible}`),
);

console.log('\n=== LOCK_1 + LOCK_2: approval token mint + verify ===');
const token = mintApprovalToken({
  service_id: 'demo-svc',
  capability: 'settle',
  operation: 'record_settle',
  nonce: 'nonce-quickstart-' + Date.now(),
  scope: { vessel_id: 'V-001', amount: 5000 },
  issued_at: Date.now(),
  expires_at: Date.now() + 60_000, // verifyApprovalToken refuses a token without one
});
console.log(`minted token digest=${digestApprovalToken(token)}`);
const payload = verifyApprovalToken(token, 'demo-svc', 'settle', 'record_settle');
console.log(`payload.capability=${payload.capability} service=${payload.service_id}`);

console.log('\n=== LOCK_5: nonce consumed once, replay rejected ===');
await verifyAndConsumeNonce(payload, defaultNonceStore);
console.log('✅ first consume OK');
try {
  await verifyAndConsumeNonce(payload, defaultNonceStore);
  console.log('❌ replay should have been rejected!');
} catch (err) {
  console.log(`✅ replay rejected: ${(err as Error).message}`);
}

console.log('\n=== LOCK_4: idempotency duplicate detection ===');
const fp = buildIdempotencyFingerprint({ amount: 5000, vessel_id: 'V-001' });
const existing = { externalRef: 'EXT-001', fingerprint: fp, status: 'settled' };
const dup = checkIdempotency('EXT-001', existing, fp, existing.fingerprint);
console.log(`isDuplicate=${dup.isDuplicate} safeNoOp=${dup.safeNoOp}`);

console.log('\n=== LOCK_3: SENSE event with before/after delta ===');
emitAegisSenseEvent({
  event_type: 'allowance.settle',
  service_id: 'demo-svc',
  capability: 'settle',
  operation: 'record_settle',
  before_snapshot: { status: 'pending' },
  after_snapshot: { status: 'settled' },
  delta: { status: 'pending→settled' },
  emitted_at: new Date().toISOString(),
  irreversible: true,
  approval_token_ref: digestApprovalToken(token),
});

console.log('\n✅ aegis-guard quickstart complete — 5 Locks demonstrated.');
