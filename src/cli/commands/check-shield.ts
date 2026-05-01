// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// AEGIS Shield — check-shield
// PreToolUse hook for Bash, Read, Write, Edit, and any MCP tool call.
// Exit 0 = allow. Exit 2 = block. Never fails open (always exits 0 on AEGIS errors).
//
// @rule:KAV-014 LakshmanRekha injection detection
// @rule:KAV-015 HanumanG is handled in check-spawn (Agent tool)
// @rule:KAV-069 MCP response injection — scan tool_result / content arrays
// @rule:KAV-070 sanitizeHistory reframe

import { readFileSync } from "fs";
import { loadConfig } from "../../core/config";
import {
  loadShieldRules,
  detectInjection,
  detectPersistenceWrite,
  detectCredentialRead,
  detectExfilSequence,
  detectMCPInjection,
} from "../../shield/injection-detector";
import { touchAgent, isStopRequested } from "../../core/db";
import { checkMudrika } from "../../kavach/mudrika-validator";

function readStdin(): string {
  try {
    return readFileSync("/dev/stdin", "utf-8");
  } catch {
    return "";
  }
}

export default async function checkShield(_args: string[]): Promise<void> {
  try {
    const stdin = readStdin().trim();
    if (!stdin) process.exit(0);

    const config = loadConfig();
    // Shield enabled check — default on if kavach.enabled
    const shieldEnabled = config.kavach?.enabled !== false;
    if (!shieldEnabled) process.exit(0);

    const enforce = config.enforcement?.mode === "enforce";

    let toolInput: Record<string, unknown>;
    try {
      toolInput = JSON.parse(stdin);
    } catch {
      process.exit(0);
    }

    const toolName = (toolInput.tool_name as string) || "";
    const sessionId = (toolInput.session_id as string) || process.env.CLAUDE_SESSION_ID || "unknown";
    const agentId = process.env.CLAUDE_AGENT_ID || sessionId;

    // @rule:KOS-062 mudrika identity check before shield scan
    const mudrika = checkMudrika(agentId);
    if (!mudrika.valid && mudrika.reason !== "no mudrika — agent not registered") {
      process.stderr.write(`\n[KAVACH:MUDRIKA] IDENTITY DENIED — ${agentId}: ${mudrika.reason}\n\n`);
      process.exit(2);
    }

    // V2-041 — touch agent in DB (last_seen + tool_calls)
    try { touchAgent(agentId); } catch {}

    // V2-048 — L1 Soft Stop: check stop_requested flag before proceeding
    try {
      if (isStopRequested(agentId)) {
        process.stderr.write(
          `\n[KAVACH:stop] L1 SOFT STOP — ${agentId} has stop_requested=1. Complete current operation and yield.\n` +
          `  Run: aegis resume ${agentId}  to see resume manifest.\n\n`
        );
        // Block further tool calls but allow current operation to complete
        if (enforce) process.exit(2);
      }
    } catch {}

    const rules = loadShieldRules();

    // --- MCP injection check — runs on all tool calls (KAV-069) ---
    // Scans tool_result / content arrays in any PreToolUse payload
    const mcpResult = detectMCPInjection(toolInput);
    if (mcpResult.verdict === "QUARANTINE") {
      emitBlock("SHIELD", mcpResult.rule_id, mcpResult.reason, mcpResult.category);
      process.exit(2);
    }

    // Tool-specific checks
    const toolInputData = (toolInput.tool_input as Record<string, unknown>) || {};

    if (toolName === "Read") {
      const filePath = (toolInputData.file_path as string) ?? "";
      if (!filePath) process.exit(0);
      const credResult = detectCredentialRead(filePath, 0, rules);
      if (credResult.verdict === "QUARANTINE") {
        emitBlock("SHIELD", credResult.rule_id, credResult.reason, credResult.category);
        process.exit(2);
      }

    } else if (toolName === "Write" || toolName === "Edit") {
      const filePath = (toolInputData.file_path as string) ?? "";
      if (!filePath) process.exit(0);
      const persResult = detectPersistenceWrite(filePath, rules);
      if (persResult.verdict === "QUARANTINE") {
        emitBlock("SHIELD", persResult.rule_id, persResult.reason, persResult.category);
        process.exit(2);
      }

    } else if (toolName === "Bash") {
      const command = (toolInputData.command as string) ?? "";
      if (!command) process.exit(0);

      // Injection pattern scan
      const scanResult = detectInjection(command, rules);
      if (scanResult.verdict === "QUARANTINE") {
        emitBlock("SHIELD", scanResult.rule_id, scanResult.reason, scanResult.category);
        process.exit(2);
      }
      if (scanResult.verdict === "BLOCK" && enforce) {
        emitBlock("SHIELD", scanResult.rule_id, scanResult.reason, scanResult.category);
        process.exit(2);
      }
      if (scanResult.verdict === "WARN" || scanResult.verdict === "BLOCK") {
        process.stderr.write(`[SHIELD] WARN (${scanResult.rule_id}): ${scanResult.reason}\n`);
      }

      // Exfil ring buffer check
      const exfilResult = detectExfilSequence(command, rules);
      if (exfilResult.verdict === "BLOCK") {
        emitBlock("SHIELD", exfilResult.rule_id, exfilResult.reason, exfilResult.category);
        if (enforce) process.exit(2);
        // Alert mode: warn but allow
        process.stderr.write(`[SHIELD] EXFIL WARNING (${exfilResult.rule_id}): ${exfilResult.reason}\n`);
      }
    }

    process.exit(0);
  } catch {
    process.exit(0); // never block on SHIELD internal errors
  }
}

function emitBlock(source: string, ruleId: string, reason: string, category: string): void {
  process.stderr.write([
    ``,
    `╔══════════════════════════════════════════════════════════════╗`,
    `║  AEGIS ${source} — BLOCKED                                       ║`,
    `╚══════════════════════════════════════════════════════════════╝`,
    ``,
    `  Rule     : ${ruleId}`,
    `  Category : ${category}`,
    `  Reason   : ${reason}`,
    ``,
    `  This action was blocked by LakshmanRekha (AEGIS Shield).`,
    `  If legitimate, add a named exemption in ~/.aegis/shield-rules.json`,
    ``,
  ].join("\n"));
}
