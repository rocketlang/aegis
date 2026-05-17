// @rocketlang/aegis-guard — AEGIS Guard SDK public API
// Five Locks proved in carbonx-backend (batches 62-74). Batch 93 makes them reusable.
// v0.2.0 adds opt-in Agentic Control Center (ACC) event bus integration.

export { IrrNoApprovalError, AegisNonceError } from './errors.js';

// @rule:ACC-003 — Opt-in event bus for Agentic Control Center observability.
//                 Stateless contract preserved (ACC-YK-003): emit is no-op
//                 when setEventBus has not been called. v0.2.0+.
export {
  type AccReceipt,
  type EventBus,
  setEventBus,
  isBusWired,
} from './acc-bus.js';

export { type NonceStore, defaultNonceStore } from './nonce.js';

export {
  type IdempotencyCheckResult,
  checkIdempotency,
  buildIdempotencyFingerprint,
} from './idempotency.js';

export {
  type AegisSenseEvent,
  type SenseTransport,
  configureSenseTransport,
  emitAegisSenseEvent,
} from './sense.js';

export {
  type QualityEvidenceInput,
  type QualityDriftInput,
  type HgGroup,
  buildQualityMaskAtPromotion,
  buildQualityDriftScore,
  HG_REQUIRED_MASKS,
  meetsHgQualityRequirement,
} from './quality.js';

export {
  type ApprovalTokenPayload,
  digestApprovalToken,
  mintApprovalToken,
  verifyApprovalToken,
  verifyAndConsumeNonce,
  verifyScopedApprovalToken,
} from './approval-token.js';

export {
  type IssueEnvelopeParams,
  type EnvelopeIssueResult,
  type EnvelopeVerifyResult,
  issueEnvelope,
  verifyEnvelope,
} from './envelope.js';
