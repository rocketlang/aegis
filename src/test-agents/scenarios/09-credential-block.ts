// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// Scenario 09 — Credential Read Block
// check-shield must block a Read tool call targeting ~/.ssh/id_rsa (credential path).
// LakshmanRekha: credential_paths detection exits 2 without needing enforce mode
// (QUARANTINE verdict fires regardless). A Read of a normal .ts file exits 0.

import { TestHarness } from "../harness.ts";

export async function run(): Promise<{ passed: boolean; details: string }> {
  const h = new TestHarness("09-credential");
  try {
    h.setup({ enforcement: { mode: "enforce" }, kavach: { enabled: true } });

    // Read targeting an SSH private key — should be QUARANTINE → exit 2
    const blockedResult = await h.callHook("check-shield", {
      tool_name: "Read",
      session_id: "test-09",
      tool_input: { file_path: "/root/.ssh/id_rsa" },
    });

    if (blockedResult.exitCode !== 2) {
      return {
        passed: false,
        details: `Expected exit 2 for .ssh/id_rsa read, got ${blockedResult.exitCode}. stderr: ${blockedResult.stderr.slice(0, 300)}`,
      };
    }
    const stderrLower = blockedResult.stderr.toLowerCase();
    if (!stderrLower.includes("shield") && !stderrLower.includes("block") && !stderrLower.includes("credential")) {
      return {
        passed: false,
        details: `Exit 2 but stderr missing credential/shield/block: ${blockedResult.stderr.slice(0, 300)}`,
      };
    }

    // Read of a normal source file — must pass through (no false positive)
    const cleanResult = await h.callHook("check-shield", {
      tool_name: "Read",
      session_id: "test-09",
      tool_input: { file_path: "/root/aegis/src/core/config.ts" },
    });

    if (cleanResult.exitCode !== 0) {
      return {
        passed: false,
        details: `Credential blocked correctly, but clean Read exited ${cleanResult.exitCode} — false positive. stderr: ${cleanResult.stderr.slice(0, 200)}`,
      };
    }

    return {
      passed: true,
      details: ".ssh/id_rsa read → exit 2 SHIELD BLOCK; normal .ts file read → exit 0 (no false positive)",
    };
  } finally {
    h.cleanup();
  }
}
