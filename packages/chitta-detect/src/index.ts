// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// @rocketlang/chitta-detect — Memory poisoning detection primitives.
//
// Extracted from /root/chitta-guard (the full Fastify service with Prisma
// persistence). This package contains ONLY the pure detection primitives —
// no DB, no HTTP, no service deps. The full service stays internal.
//
// Public surface:
//   import { trust, imperative, toolOutput, capabilityExpansion,
//            fingerprint, rateLimit, retrospective, scan }
//   from '@rocketlang/chitta-detect';
//
//   trust.resolve(content, sourceMetadata)
//   imperative.scan(content)
//   toolOutput.classify(toolOutput, agentRole, provenanceRecord)
//   capabilityExpansion.scan(content)
//   fingerprint.scan(content)                  // 16 bootstrap patterns
//   fingerprint.register({ id, category, ... }) // append-only
//   rateLimit.check(agentId)
//   retrospective.audit(contentHash, ts, agentId)
//   scan.evaluate(content, agentContext, thresholdConfig)  // orchestrator

export * as trust from './trust.js';
export * as imperative from './imperative.js';
export * as toolOutput from './tool-output.js';
export * as capabilityExpansion from './capability-expansion.js';
export * as fingerprint from './fingerprint.js';
export * as rateLimit from './rate-limit.js';
export * as retrospective from './retrospective.js';
export * as scan from './scan.js';

// @rule:ACC-003 — Opt-in event bus for Agentic Control Center observability.
//                 Stateless contract preserved (ACC-YK-003): emit is no-op
//                 when setEventBus has not been called. v0.2.0+.
export {
  type AccReceipt,
  type EventBus,
  setEventBus,
  isBusWired,
} from './acc-bus.js';

// Re-export the types most consumers will name explicitly
export type { SourceMetadata, TrustClassification, TrustClassifyResult } from './trust.js';
export type { ImperativeScanResult } from './imperative.js';
export type { ToolOutputClassifyResult } from './tool-output.js';
export type { CapabilityExpansionMatch } from './capability-expansion.js';
export type { RateLimitStatus } from './rate-limit.js';
export type { ChunkAuditRecord, AuditStatus } from './retrospective.js';
export type { FingerprintPattern, FingerprintCategory, FingerprintScanResult } from './fingerprint.js';
export type { AgentContext, ScanResult, ScanVerdict, ThresholdConfig } from './scan.js';
