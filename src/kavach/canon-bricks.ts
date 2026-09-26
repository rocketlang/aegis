// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// Optional canon bricks — @ankr/approve and @ankr/mask-authorize.
//
// These live on ANKR's internal registry; a PUBLIC `npm install @xshieldai/aegis` cannot
// fetch them (they 404 on npmjs). They are therefore optionalDependencies, and this module
// loads the real brick when present and a behaviour-identical LOCAL FLOOR when not (FP-010:
// every capability has a zero-dependency floor). Same try/catch-require pattern the EE
// modules use in dashboard/server.ts. On ANKR's own network the real bricks load, so
// nothing changes there; only a public install runs on the floor.

import { createRequire } from "module";
const require = createRequire(import.meta.url);

// ── @ankr/approve — a lawful-transition state machine ───────────────────────────
export type ApprovalEngine = { assertLawful(status: string, action: string): string };
type Machine = Record<string, { from: string[]; to: string }>;

// The floor: the transition table IS the definition (the caller passes it in), so this is
// the same behaviour as the brick, not a fork — assertLawful returns the target state or
// throws on an unlawful transition.
function floorApprovalEngine(machine: Machine): ApprovalEngine {
  return {
    assertLawful(status, action) {
      const t = machine[action];
      if (t && t.from.includes(status)) return t.to;
      throw new Error(`unlawful transition: ${status} --${action}-->`);
    },
  };
}

export function loadCreateApprovalEngine(): (m: Machine) => ApprovalEngine {
  try {
    const brick = require("@ankr/approve");
    if (brick && typeof brick.createApprovalEngine === "function") return brick.createApprovalEngine;
  } catch { /* brick absent — public install runs on the floor */ }
  return floorApprovalEngine;
}

// ── @ankr/mask-authorize — a bitmask authorization check ────────────────────────
export interface MaskAuthorizeInput {
  caller: bigint;
  required: bigint;
  capability?: bigint;
  mode?: "any" | "all";
  callerLabel?: string;
  targetLabel?: string;
}
export interface MaskAuthorizeResult { authorized: boolean }

// The floor: role-mask AND, mode 'any' (any required bit grants) vs 'all' (all required
// bits), with an optional capability bit AND-ed in. This is the BMOS-006 semantics the
// call site documents, computed directly.
function floorMaskAuthorize(i: MaskAuthorizeInput): MaskAuthorizeResult {
  const base =
    i.required === 0n ? true
    : i.mode === "all" ? (i.caller & i.required) === i.required
    : (i.caller & i.required) !== 0n; // 'any' (default)
  const cap = i.capability === undefined ? true : (i.caller & i.capability) !== 0n;
  return { authorized: base && cap };
}

export function loadMaskAuthorize(): (i: MaskAuthorizeInput) => MaskAuthorizeResult {
  try {
    const brick = require("@ankr/mask-authorize");
    if (brick && typeof brick.authorize === "function") return brick.authorize;
  } catch { /* brick absent — public install runs on the floor */ }
  return floorMaskAuthorize;
}

// Exported for the test that pins floor == brick semantics.
export const __floor = { floorApprovalEngine, floorMaskAuthorize };
