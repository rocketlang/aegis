// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// OSS-safe EE gate.
//
// `ee/license.ts` is BSL-licensed and is NOT shipped in the AGPL (npm) build — it is not in
// package.json `files`. A STATIC value import of it therefore throws "Cannot find module"
// the moment the importing file loads. Before 2.7.0 `src/dashboard/server.ts` and
// `src/cli/commands/status.ts` imported `isEE`/`eeStatus` from it directly, so the whole
// dashboard and `aegis status` could not start from a public install.
//
// This module ships in the core, and gives the same two functions. When the EE module IS
// present (an enterprise build) it defers to it, so a richer license check there still
// wins; when it is absent it answers from the environment, exactly as ee/license does
// today. The require is lazy and in a try/catch, the pattern the other EE touch-points
// (pramana-emit, gate, monitor) already use.
// @rule:KOS-T110

type EeLicense = { isEE?: () => boolean; eeStatus?: () => string };

let _ee: EeLicense | null | undefined;
function eeModule(): EeLicense | null {
  if (_ee !== undefined) return _ee;
  try {
    _ee = require("../../ee/license") as EeLicense;
  } catch {
    _ee = null; // EE module absent (AGPL-only distribution)
  }
  return _ee;
}

export function isEE(): boolean {
  const m = eeModule();
  if (m && typeof m.isEE === "function") return m.isEE();
  return !!(process.env.AEGIS_EE_LICENSE_KEY && process.env.AEGIS_EE_LICENSE_KEY.trim().length > 0);
}

export function eeStatus(): string {
  const m = eeModule();
  if (m && typeof m.eeStatus === "function") return m.eeStatus();
  return isEE() ? "active" : "not licensed (AGPL3 core running)";
}
