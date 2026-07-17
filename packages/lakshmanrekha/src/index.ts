// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// @rocketlang/lakshmanrekha — LLM endpoint probe suite for AI agent security.
//
// Extracted from xshieldai-asm-ai-module (the full Fastify service with
// SQLite-backed attestations and Forja STATE/TRUST/SENSE/PROOF endpoints).
// This package contains ONLY the probe primitives — 8 deterministic
// behavioral attack probes + 4 HTTP-surface probes (v0.3.0), a
// deterministic regex classifier, and runners that call user-provided
// LLM endpoints / inspect their surface.
//
// Public surface:
//   import {
//     PROBE_REGISTRY, getProbe, getProbes,
//     classifyResponse, computeRefusalRate,
//     runProbe, runAllProbes, maskKey,
//   } from '@rocketlang/lakshmanrekha';

export {
  PROBE_REGISTRY,
  getProbe,
  getProbes,
} from './registry.js';

export type { ProbeVerdict, ProbeDefinition } from './registry.js';

export {
  classifyResponse,
  computeRefusalRate,
  REFUSAL_PATTERN_SET,
  COMPLIANCE_PATTERN_SET,
} from './classifier.js';

export {
  runProbe,
  runAllProbes,
  maskKey,
} from './runner.js';

export type { RunProbeOptions, ProbeRunResult } from './runner.js';

// --- Surface probes (v0.3.0) — probe the ENDPOINT's HTTP surface, not the
// model's prose. Born from the 2026-07-17 open-gateway/RCE incident that every
// behavioral probe would have passed. See surface-registry.ts header.
export {
  SURFACE_PROBE_REGISTRY,
  getSurfaceProbe,
  getSurfaceProbes,
} from './surface-registry.js';

export type {
  SurfaceProbeDefinition,
  SurfaceVerdict,
  SurfaceCategory,
} from './surface-registry.js';

export {
  runSurfaceProbe,
  runAllSurfaceProbes,
  countExposed,
} from './surface-runner.js';

export type { RunSurfaceProbeOptions, SurfaceProbeResult } from './surface-runner.js';

// @rule:ACC-003 — Opt-in event bus for Agentic Control Center observability.
//                 Stateless contract preserved (ACC-YK-003): emit is no-op
//                 when setEventBus has not been called. v0.2.0+.
export {
  type AccReceipt,
  type EventBus,
  setEventBus,
  isBusWired,
} from './acc-bus.js';
