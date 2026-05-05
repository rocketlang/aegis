# @ankr/aegis-guard

AEGIS Guard SDK — reusable approval-token, nonce, idempotency, SENSE, and quality-evidence primitives for AEGIS-governed services.

**Carbonx proved the locks. Batch 93 makes the locks reusable.**

The Five Locks were proven across 13 batches (62–74) of carbonx-backend. This package extracts them into a service-agnostic SDK so any AEGIS-governed service can adopt them without copy-pasting bespoke logic.

## Five Locks

| Lock | Primitive | Rule |
|---|---|---|
| LOCK_1 — decision | `verifyApprovalToken` | AEG-E-016 |
| LOCK_2 — identity | `verifyScopedApprovalToken` | AEG-E-016 |
| LOCK_3 — observability | `emitAegisSenseEvent` | CA-003, AEG-HG-2B-003/005 |
| LOCK_4 — rollback | `checkIdempotency` | AEG-HG-2B-006 |
| LOCK_5 — idempotency | `verifyAndConsumeNonce` | AEG-HG-2B-006 |

## Install

```bash
bun add @ankr/aegis-guard
```

## Usage

### LOCK_1 + LOCK_2 — decision + identity

```typescript
import { verifyApprovalToken, verifyScopedApprovalToken } from '@ankr/aegis-guard';

// LOCK_1 — base token verification (service_id + capability + operation)
const payload = verifyApprovalToken(token, 'my-service', 'settle', 'record_settle');

// LOCK_2 — scoped verification (add service-specific field bindings)
const payload = verifyScopedApprovalToken(
  token, 'my-service', 'settle', 'record_settle',
  { vessel_id: args.vesselId, amount: args.amount },
);
```

### LOCK_3 — observability (SENSE)

```typescript
import { emitAegisSenseEvent, digestApprovalToken, configureSenseTransport } from '@ankr/aegis-guard';

// Wire your logger (default: process.stdout JSON)
configureSenseTransport((event) => logger.info(event, `SENSE:${event.event_type}`));

emitAegisSenseEvent({
  event_type: 'allowance.settle',
  service_id: 'my-service',
  capability: 'settle',
  operation: 'record_settle',
  before_snapshot: { status: 'pending' },
  after_snapshot:  { status: 'settled' },
  delta:           { status: 'pending→settled' },
  emitted_at: new Date().toISOString(),
  irreversible: true,
  correlation_id: req.headers['x-correlation-id'],
  approval_token_ref: digestApprovalToken(token), // 24-hex digest, never raw token
});
```

### LOCK_4 — rollback guard (idempotency check)

```typescript
import { checkIdempotency, buildIdempotencyFingerprint } from '@ankr/aegis-guard';

const existing = await db.findByExternalRef(args.externalRef);
const fp = buildIdempotencyFingerprint({ amount: args.amount, vessel_id: args.vesselId });
const { isDuplicate, safeNoOp } = checkIdempotency(args.externalRef, existing, fp, existing?.fingerprint);

if (isDuplicate && safeNoOp) return existing; // safe no-op
if (isDuplicate && !safeNoOp) throw new Error('payload mismatch on duplicate externalRef');
```

### LOCK_5 — nonce replay prevention

```typescript
import { verifyAndConsumeNonce } from '@ankr/aegis-guard';

// Requires nonce in payload; throws IrrNoApprovalError on missing or replayed nonce
await verifyAndConsumeNonce(payload, redisNonceStore);
```

### Quality evidence

```typescript
import { buildQualityMaskAtPromotion, meetsHgQualityRequirement } from '@ankr/aegis-guard';

const mask = buildQualityMaskAtPromotion({
  tests_passed: true,
  rollback_tested: true,
  audit_artifact_produced: true,
});

const ready = meetsHgQualityRequirement('HG-2B-financial', mask);
```

## NonceStore — production wiring

The default `defaultNonceStore` is in-memory (single-process only). Multi-instance deployments must provide a Redis-backed store:

```typescript
import { type NonceStore } from '@ankr/aegis-guard';

const redisNonceStore: NonceStore = {
  async consumeNonce(nonce, ttlMs) {
    const key = `aegis:nonce:${nonce}`;
    const result = await redis.set(key, '1', 'NX', 'PX', ttlMs);
    if (result === null) return false; // already consumed
    return true;
    // throws propagate to callers → fail CLOSED (AEG-HG-2B-006)
  },
};
```

## Schema

- `quality_mask_at_promotion`: bits 0–11, `aegis-quality-16bit-v1`
- `quality_drift_score`: bits 12–15, `aegis-quality-16bit-v1`
- AEG-Q-003 invariant: bits 12–15 must **never** be set in `quality_mask_at_promotion`

## License

AGPL-3.0 — Capt. Anil Sharma, powerpbox.org
