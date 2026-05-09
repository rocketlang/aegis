// SPDX-License-Identifier: AGPL-3.0-only
// AEGIS — Public SDK entry point
//
// Lite (beginners — no setup required):
//   import { lite, TRUST_PERM, ROLE_MASK } from '@rocketlang/aegis'
//
// Full (advanced — wraps enforcement registry):
//   import { aegis } from '@rocketlang/aegis'

export { lite, TRUST_PERM, ROLE_MASK, AegisLiteError } from './src/sdk/lite.js';
export type { LiteAgent, LiteGuardResult, TrustPerm } from './src/sdk/lite.js';

export { aegis } from './src/sdk/index.js';
export type { AegisGuardRequest, AegisGuardResult } from './src/sdk/index.js';
