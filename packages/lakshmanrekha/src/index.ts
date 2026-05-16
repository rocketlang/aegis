// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// @rocketlang/lakshmanrekha — LLM endpoint probe suite for AI agent security.
//
// Extracted from xshieldai-asm-ai-module (the full Fastify service with
// SQLite-backed attestations and Forja STATE/TRUST/SENSE/PROOF endpoints).
// This package contains ONLY the probe primitives — 8 deterministic
// attack probes, a deterministic regex classifier, and a runner that
// calls user-provided LLM endpoints.
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
