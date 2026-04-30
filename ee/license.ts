// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See ee/LICENSE-EE for terms.

// KOS-T110: EE license gate
// Reads AEGIS_EE_LICENSE_KEY env var. Any non-empty value activates EE.
// Production deployments: set to a signed key issued by the Licensor.

export function isEE(): boolean {
  return !!(process.env.AEGIS_EE_LICENSE_KEY && process.env.AEGIS_EE_LICENSE_KEY.trim().length > 0);
}

export function eeStatus(): "active" | "not licensed (AGPL3 core running)" {
  return isEE() ? "active" : "not licensed (AGPL3 core running)";
}
