// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// AEGIS chitta-guard hook — check-chitta
// PreToolUse hook for Write and Edit operations on protected memory paths.
// Scans content before it enters agent persistent memory (GRANTHX, .claude/, proposals/, ankr-todos/).
// Fails open — chitta-guard unreachable = allow (never block tool execution on infra failure).
//
// @rule:CG-001 — all content entering agent persistent memory must pass a scan
// @rule:CG-T-009 — AEGIS PreToolUse hook integration for Write/Edit on memory paths

import { readFileSync } from "fs";

const CHITTA_GUARD_URL = process.env.CHITTA_GUARD_URL ?? "http://localhost:4257";
const SCAN_TIMEOUT_MS = 3000;

// Protected paths — writing to these = potential memory poisoning vector
const PROTECTED_PATH_SEGMENTS = [
  ".claude/",
  "proposals/",
  "ankr-todos/",
  ".ankr/config/",
  "bitmask-os-codex/",
  "codex.json",
];

function readStdin(): string {
  try {
    return readFileSync("/dev/stdin", "utf-8");
  } catch {
    return "";
  }
}

function isProtectedPath(filePath: string): boolean {
  return PROTECTED_PATH_SEGMENTS.some(seg => filePath.includes(seg));
}

function extractContent(toolName: string, input: Record<string, unknown>): string {
  if (toolName === "Write") return String(input.content ?? "");
  if (toolName === "Edit")  return String(input.new_string ?? "");
  return "";
}

export default async function checkChitta(_args: string[]): Promise<void> {
  const stdin = readStdin().trim();
  if (!stdin) process.exit(0);

  let event: Record<string, unknown>;
  try {
    event = JSON.parse(stdin);
  } catch {
    process.exit(0);
  }

  const toolName = String(event.tool_name ?? event.name ?? "");
  if (toolName !== "Write" && toolName !== "Edit") process.exit(0);

  const input = (event.tool_input ?? event.input ?? {}) as Record<string, unknown>;
  const filePath = String(input.file_path ?? "");
  if (!isProtectedPath(filePath)) process.exit(0);

  const content = extractContent(toolName, input);
  // Only scan non-trivial content (< 20 chars is unlikely to carry injection)
  if (content.length < 20) process.exit(0);

  const agentId = String(event.session_id ?? "aegis-hook-unknown");
  const sessionId = String(event.session_id ?? "");

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), SCAN_TIMEOUT_MS);

    const response = await fetch(`${CHITTA_GUARD_URL}/api/v2/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        content,
        agent_id: agentId,
        session_id: sessionId || undefined,
        scan_type: "memory_write",
        source_metadata: {
          source_type: "internal",
          declared_trust: "TRUSTED",
        },
      }),
      signal: controller.signal,
    });

    clearTimeout(timeout);

    if (!response.ok) process.exit(0); // fail open on HTTP errors

    const result = await response.json() as {
      verdict: string;
      confidence: number;
      rules_fired: string[];
      quarantine_id?: string;
      scan_id: string;
    };

    if (result.verdict === "BLOCK") {
      // @rule:CG-001 — BLOCK = discard, do not persist
      process.stderr.write(
        `[chitta-guard] BLOCK — ${result.rules_fired.join(", ")} confidence=${result.confidence} ` +
        `scan_id=${result.scan_id} path=${filePath}\n`
      );
      process.exit(2);
    }

    if (result.verdict === "INJECT_SUSPECT") {
      // @rule:CG-008 — content quarantined, warn operator, allow write to proceed
      // PostToolUse cannot block; Write is allowed but quarantine record is created in chitta-guard
      process.stderr.write(
        `[chitta-guard] INJECT_SUSPECT — ${result.rules_fired.join(", ")} confidence=${result.confidence} ` +
        `quarantine_id=${result.quarantine_id ?? "none"} scan_id=${result.scan_id} path=${filePath}\n`
      );
      // Allow write to proceed (memory write in .claude/ / proposals/ is from this agent, not external)
      process.exit(0);
    }

    // PASS or ADVISORY — allow
    process.exit(0);

  } catch {
    // Fail open — chitta-guard unavailable = don't block tool execution
    process.exit(0);
  }
}
