// @ankr/aegis-guard — AEGIS Guard SDK public API
// Five Locks proved in carbonx-backend (batches 62-74). Batch 93 makes them reusable.

export { IrrNoApprovalError, AegisNonceError } from './errors.js';

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
