# @rocketlang/aegis-guard

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
bun add @rocketlang/aegis-guard
# or
npm install @rocketlang/aegis-guard
```

## Usage

### LOCK_1 + LOCK_2 — decision + identity

```typescript
import { verifyApprovalToken, verifyScopedApprovalToken } from '@rocketlang/aegis-guard';

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
import { emitAegisSenseEvent, digestApprovalToken, configureSenseTransport } from '@rocketlang/aegis-guard';

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
import { checkIdempotency, buildIdempotencyFingerprint } from '@rocketlang/aegis-guard';

const existing = await db.findByExternalRef(args.externalRef);
const fp = buildIdempotencyFingerprint({ amount: args.amount, vessel_id: args.vesselId });
const { isDuplicate, safeNoOp } = checkIdempotency(args.externalRef, existing, fp, existing?.fingerprint);

if (isDuplicate && safeNoOp) return existing; // safe no-op
if (isDuplicate && !safeNoOp) throw new Error('payload mismatch on duplicate externalRef');
```

### LOCK_5 — nonce replay prevention

```typescript
import { verifyAndConsumeNonce } from '@rocketlang/aegis-guard';

// Requires nonce in payload; throws IrrNoApprovalError on missing or replayed nonce
await verifyAndConsumeNonce(payload, redisNonceStore);
```

### Quality evidence

```typescript
import { buildQualityMaskAtPromotion, meetsHgQualityRequirement } from '@rocketlang/aegis-guard';

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
import { type NonceStore } from '@rocketlang/aegis-guard';

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

---

## v0.2.0 — Opt-in Agentic Control Center (ACC) event bus

Added 2026-05-17. Each Five Locks primitive now emits an `AccReceipt` on
success or failure, **but only when you wire a bus**. Without `setEventBus`,
v0.2.0 behaves identically to v0.1.0 — no emission, no state, no side effect.

### Wire it in 3 lines

```typescript
import { setEventBus, type EventBus, type AccReceipt } from '@rocketlang/aegis-guard';

const myBus: EventBus = {
  emit: (r: AccReceipt) => console.log(`[ACC] ${r.event_type} verdict=${r.verdict} ${r.summary}`),
};
setEventBus(myBus);
```

Now every primitive call emits a receipt. Pass `null` to `setEventBus` to detach.

### Receipt events emitted

| Primitive | event_type on success | event_type on failure |
|---|---|---|
| `verifyApprovalToken` | `lock.approval.verified` (PASS) | `lock.approval.rejected` (FAIL) |
| `verifyAndConsumeNonce` | `lock.nonce.consumed` (PASS) | `lock.nonce.rejected` (FAIL) |
| `checkIdempotency` | `lock.idempotency.duplicate` (PASS) OR `lock.idempotency.mismatch` (WARN) | (no event for non-duplicate path) |
| `emitAegisSenseEvent` | `lock.sense.emitted` (PASS or WARN if irreversible) | — |

### Receipt shape

```typescript
interface AccReceipt {
  receipt_id: string;       // primitive-prefixed identifier
  primitive: string;        // always 'aegis-guard' for this package
  event_type: string;       // lock.*
  emitted_at: string;       // ISO 8601
  agent_id?: string;        // reserved — not yet populated by aegis-guard
  verdict?: string;         // PASS | FAIL | WARN
  rules_fired?: string[];   // e.g. ['AEG-E-016']
  summary?: string;         // ≤200 chars
  payload?: Record<string, unknown>;
}
```

The shape is a strict subset of the EE PRAMANA receipt format. EE
consumers ingest these events without translation.

### Phase-1 limits (v0.2.0)

- **agent_id is not yet populated** — primitives don't receive an agent
  context as parameter. Future versions may add an optional `agent_id`
  argument to each primitive; today you can post-process receipts in the
  bus to add agent context from your own tracking.
- **`buildIdempotencyFingerprint`, `digestApprovalToken`, `mintApprovalToken`
  do NOT emit** — they're pure helpers called many times per operation.
  Emitting from them would flood the bus.
- **`buildQualityMaskAtPromotion`, `buildQualityDriftScore`,
  `meetsHgQualityRequirement` do NOT emit** — quality computation is
  scoring, not a governance decision. They're called during promotion
  decisions; the calling code emits the governance event.
- **Default bus is in-process only.** Multi-process buses (Redis-backed,
  etc.) are a consumer choice — implement the `EventBus` interface and
  call `setEventBus(yourBus)`.

### Use with `@rocketlang/aegis-suite`

If you installed the meta-package, you can wire all 6 primitives in one call:

```typescript
import { wireAllToBus } from '@rocketlang/aegis-suite';  // available in suite v0.2.0+
wireAllToBus();  // default: in-memory bus + SQLite writer to ~/.aegis/acc-events.db
```

This sets up the bus on aegis-guard + chitta-detect + lakshmanrekha + hanumang-mandate
all at once, and persists events for the Agentic Control Center page.

### Discipline

- **Stateless contract preserved.** Primitives hold no state beyond a
  module-private bus reference. Pass `null` to `setEventBus` to detach.
- **Emission must never throw.** If your bus implementation throws,
  the primitive's caller is unaffected — the receipt is silently dropped.
  This is intentional; observability must not break the governed path.
