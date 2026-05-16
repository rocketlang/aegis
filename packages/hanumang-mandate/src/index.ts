// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// @rocketlang/hanumang-mandate — Agent delegation credential + 7-axis posture scoring.
//
// Extracted from xshieldai-hanumang (the full Fastify service with SQLite-
// backed attestations, Forja STATE/TRUST/SENSE/PROOF endpoints, and
// Phase-2 regression alert routing). This package contains ONLY the
// pure primitives — Mudrika credential verification + 7-axis scorer.
//
// COMPLEMENTARY to @rocketlang/aegis HanumanG (spawn-time governance):
//   @rocketlang/aegis      → "Can this agent SPAWN?" (PreToolUse gate)
//   @rocketlang/hanumang-mandate → "Is this agent's MANDATE valid?" + posture
//
// Public surface:
//   import {
//     verifyMudrika, scoreAxis, computePostureScore,
//   } from '@rocketlang/hanumang-mandate';

export {
  verifyMudrika,
} from './mudrika.js';

export type {
  MudrikaPayload,
  VerifyOutcome,
  VerifyResult,
} from './mudrika.js';

export {
  scoreAxis,
  computePostureScore,
} from './scorer.js';

export type {
  Axis,
  AxisOutcome,
  AxisInput,
  AxisScore,
  PostureScore,
} from './scorer.js';
