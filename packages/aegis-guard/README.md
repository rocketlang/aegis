# @xshieldai/aegis-guard

> **🔍 Verification status (2026-10-05 IST — v0.4.0)**
> - **Tests:** ✅ **177/177 passing** in the repository; the npm package ships `src/` only, so run them from a clone (`bun test`): 70 in [tests/aegis-guard.test.ts](https://github.com/rocketlang/aegis/blob/master/packages/aegis-guard/tests/aegis-guard.test.ts) and 107 in [tests/hardening.test.ts](https://github.com/rocketlang/aegis/blob/master/packages/aegis-guard/tests/hardening.test.ts) for key trust, malformed tokens, nonces, the duplicate check, the audit event, the quality bar, the envelope helpers and the stated limits. No test contacts a network or touches `~/.aegis`.
> - **Examples:** ✅ runnable quickstart, in the repository (not in the npm package): [examples/quickstart.ts](https://github.com/rocketlang/aegis/blob/master/packages/aegis-guard/examples/quickstart.ts) — `bun run examples/quickstart.ts` shows all 5 Locks in action with receipts
> - **Live demo:** ⚠️ planned (Tier 3, see [PROOF-STACK.md](https://github.com/rocketlang/aegis/blob/master/PROOF-STACK.md))
> - **Limits:** see "What this does not do" below, and the v0.2.0 ACC section
> - **Upgrading from 0.3.x:** some calls that passed are now refused, and minting no longer makes a key. See "Upgrading from 0.3.x".

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
bun add @xshieldai/aegis-guard
# or
npm install @xshieldai/aegis-guard
```

## Keys — who signs, who verifies

An approval token is an EdDSA-signed JWT. One box signs; every other box only verifies.

| Box | Holds | Set up by |
|---|---|---|
| The approving authority (AEGIS) | `~/.aegis/approval-signing.key` and `.pub` | `ensureSigningKeypair()`, once, at boot |
| Every service that checks approvals | the authority's **public** key | the file `~/.aegis/approval-signing.pub`, or the PEM in `AEGIS_APPROVAL_PUBKEY_PEM` |

`AEGIS_DIR` replaces `~/.aegis`. The rules the package enforces (`AEG-HG-2B-007`):

- **Minting never makes a key.** `mintApprovalToken()` throws on a box with no private key.
- **A box that was given a public key never makes its own.** `ensureSigningKeypair()` throws there and writes nothing.
- **Keys that disagree are not trusted.** If the private key, the public file and the environment PEM are not all the same Ed25519 key, every verification is refused and the reason names the conflict.
- **No key, no approval.** With no key material at all, verification is refused.

## Usage

### LOCK_1 + LOCK_2 — decision + identity

`verifyApprovalToken()` checks, in order: the signature; that service, capability and operation match exactly; that `expires_at` is a number and not past; that `issued_at`, when present, is a number, not more than 60 seconds ahead of the clock and not after `expires_at`; that `status`, when present, is exactly `approved`. Anything else throws `IrrNoApprovalError` (`code: 'IRR-NOAPPROVAL'`) — including a token that is not text.

Mint with `issued_at` and `expires_at` in milliseconds: `mintApprovalToken({ service_id, capability, operation, nonce, issued_at: Date.now(), expires_at: Date.now() + 60_000 })`.

```typescript
import { verifyApprovalToken, verifyScopedApprovalToken } from '@xshieldai/aegis-guard';

// LOCK_1 — base token verification (service_id + capability + operation)
const payload = verifyApprovalToken(token, 'my-service', 'settle', 'record_settle');

// LOCK_2 — scoped verification (add service-specific field bindings)
const payload = verifyScopedApprovalToken(
  token, 'my-service', 'settle', 'record_settle',
  { vessel_id: args.vesselId, amount: args.amount },
);
```

Each scope field must be the token's own field and strictly equal (`100` is not `"100"`). A field the caller has no value for (`undefined` or `null`) is refused: it would bind the token to nothing.

### LOCK_3 — observability (SENSE)

```typescript
import { emitAegisSenseEvent, digestApprovalToken, configureSenseTransport } from '@xshieldai/aegis-guard';

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

If `approval_token_ref` is not already a 24-hex digest, the SDK digests it before the event reaches the transport or the bus, so a raw token passed by mistake is not written to the log.

### LOCK_4 — rollback guard (idempotency check)

```typescript
import { checkIdempotency, buildIdempotencyFingerprint } from '@xshieldai/aegis-guard';

const existing = await db.findByExternalRef(args.externalRef);
const fp = buildIdempotencyFingerprint({ amount: args.amount, vessel_id: args.vesselId });
const { isDuplicate, safeNoOp } = checkIdempotency(args.externalRef, existing, fp, existing?.fingerprint);

if (isDuplicate && safeNoOp) return existing; // safe no-op
if (isDuplicate && !safeNoOp) throw new Error('duplicate externalRef: payload differs or cannot be compared');
```

A duplicate is a safe no-op only when **both** fingerprints are present and equal (`AEG-HG-2B-009`). If the existing record has no stored fingerprint, the result is `safeNoOp: false, comparable: false`: store the fingerprint with the record.

`buildIdempotencyFingerprint()` sorts keys at every depth and keeps `NaN`, `±Infinity`, `bigint`, `Map` and `Set` distinct. The fingerprint is the payload, base64-encoded — **not a hash**. Anyone who can read a stored fingerprint can read the payload; keep secrets out of it or hash it before storing.

### LOCK_5 — nonce replay prevention

```typescript
import { verifyAndConsumeNonce } from '@xshieldai/aegis-guard';

// Requires nonce in payload; throws IrrNoApprovalError on missing or replayed nonce
await verifyAndConsumeNonce(payload, redisNonceStore);
```

The nonce must be non-empty text and the payload must be in date. Only a store that answers exactly `true` has consumed the nonce; a store that throws propagates its error (fail closed). This call takes a payload and checks no signature: pass it what `verifyApprovalToken()` returned.

### Quality evidence

```typescript
import { buildQualityMaskAtPromotion, meetsHgQualityRequirement } from '@xshieldai/aegis-guard';

const mask = buildQualityMaskAtPromotion({
  tests_passed: true,
  rollback_tested: true,
  audit_artifact_produced: true,
});

const ready = meetsHgQualityRequirement('HG-2B-financial', mask);
// false here: the financial bar needs all twelve promotion bits
```

`meetsHgQualityRequirement()` returns `false` for a group that is not in the table and for a mask that is not a whole number made of bits 0–11 (`-1`, `"4095"`, `4095.9`, or a mask with a drift bit set). `HG_REQUIRED_MASKS` is frozen.

### Session envelope

```typescript
import { issueEnvelope, verifyEnvelope } from '@xshieldai/aegis-guard';

const env = await issueEnvelope({ service_key: 'my-service', declared_caps: ['read'] });
const audit = await verifyEnvelope(env.session_id);
if (!audit.verified || audit.drift_detected) { /* quarantine the session */ }
```

Both call the Aegis dashboard (`aegis_url`, or `AEGIS_URL`, or `http://localhost:4850`; http and https only) and read its answer strictly (`ASE-016`): `verified` is true only when the answer says exactly `true` for the session asked about; an answer with no session id or seal throws. They trust that endpoint and the connection to it — they do not recompute the seal.

## NonceStore — production wiring

The default `defaultNonceStore` is in-memory (single-process only). Multi-instance deployments must provide a Redis-backed store:

```typescript
import { type NonceStore } from '@xshieldai/aegis-guard';

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

## Upgrading from 0.3.x

- **Call `ensureSigningKeypair()` once on the authority box before minting.** Minting no longer makes a key. On a verifier box, do not call it at all.
- **Mint with a numeric `expires_at`.** A token without one is refused (it used to never expire).
- **`verifyApprovalToken()` refuses a `status` other than `approved`.** Before, only the scoped call looked at it.
- **`checkIdempotency()` without a stored fingerprint is no longer a safe no-op.** Read the new `comparable` field.
- **Fingerprints of nested payloads change** (inner keys are now sorted). A flat payload of text, finite numbers, booleans and null fingerprints as before. A retry that straddles the upgrade with a nested payload is reported as a mismatch.
- **A stale `approval-signing.pub` next to the private key is now a conflict**, and verification is refused until the two agree.
- `verifyEnvelope()` throws when the audit is for another session; `issueEnvelope()` throws on an answer with no session id or seal.

## What this does not do

Each of these is pinned by a test in `tests/hardening.test.ts`, so it cannot change unnoticed — except the two about what is absent (a shared nonce store, a revocation list), which no test can show.

- **No upper limit on a token's life.** The signer chooses `expires_at`.
- **An empty scope checks nothing more** than `verifyApprovalToken()`. A scope value that is an object never matches.
- **`verifyAndConsumeNonce()` checks no signature and no status.** It trusts the payload it is given.
- **A key file swapped under a running process is not noticed until restart.** A change of `AEGIS_APPROVAL_PUBKEY_PEM` is.
- **The default nonce store is one process's memory.** Two instances each accept the same nonce once.
- **The fingerprint is not a hash**, a field set to `undefined` is the same as the field absent, and a `Date` is the same as its ISO text.
- **Only the `approval_token_ref` field is digested.** A raw token placed anywhere else in a SENSE event reaches the transport.
- **A SENSE transport that throws reaches the caller**, and the three snapshots are not checked for presence.
- **Revocation is a field in the token.** There is no revocation list: a token signed as `approved` stays valid until it expires.

## License

AGPL-3.0 — Capt. Anil Sharma, powerpbox.org

---

## v0.2.0 — Opt-in Agentic Control Center (ACC) event bus

Added 2026-05-17. Each Five Locks primitive now emits an `AccReceipt` on
success or failure, **but only when you wire a bus**. Without `setEventBus`,
v0.2.0 behaves identically to v0.1.0 — no emission, no state, no side effect.

### Wire it in 3 lines

```typescript
import { setEventBus, type EventBus, type AccReceipt } from '@xshieldai/aegis-guard';

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
| `checkIdempotency` | `lock.idempotency.duplicate` (PASS), `lock.idempotency.mismatch` (WARN) or `lock.idempotency.unverifiable` (WARN, no fingerprint to compare) | (no event for non-duplicate path) |
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

### Use with `@xshieldai/aegis-suite`

If you installed the meta-package, you can wire all 6 primitives in one call:

```typescript
import { wireAllToBus } from '@xshieldai/aegis-suite';  // available in suite v0.2.0+
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
