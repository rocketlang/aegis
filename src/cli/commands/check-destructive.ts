// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// KAVACH Gate — check-destructive
// PreToolUse hook for Bash, Write, Edit, Read tools.
// Exit 0 = allow. Exit 2 = block (Claude Code will not execute the tool).
//
// Level 0: (perm_mask & required_bits) !== 0        — O(1), silent block  (KAV-061)
// Level 1: (class_mask & resource_class_bits) !== 0  — O(1), silent block  (KAV-062)
// Level 2: DAN pattern match → KAVACH Gate (human approval)               (KAV-052)
//
// @rule:KAV-052 — pre-execution intercept for all destructive actions
// @rule:KAV-061 — Level 0 perm_mask enforcement
// @rule:KAV-062 — Level 1 class_mask enforcement
// @rule:KAV-YK-014 — three-level enforcement ordering

import { readFileSync, existsSync } from "fs";
import { join } from "path";
import { DASHBOARD_PORT } from "../../core/config";
import { requiredBitsForTool } from "../../kavach/perm-mask";
import { classifyResource, extractResourceFromToolInput } from "../../kavach/class-mask";
import { checkValve, incrementLoopCount } from "../../kavach/gate-valve";
import { checkMudrika } from "../../kavach/mudrika-validator";

const AEGIS_DIR = join(process.env.HOME || "/root", ".aegis");
const RULES_PATH = join(AEGIS_DIR, "destructive-rules.json");

interface DestructiveRule {
  pattern: string;
  flags: string;
  reason: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM";
}

interface DestructiveRules {
  bash_block_patterns: DestructiveRule[];
  allowed_override_token: string;
}

function loadRules(): DestructiveRules | null {
  try {
    if (!existsSync(RULES_PATH)) return null;
    return JSON.parse(readFileSync(RULES_PATH, "utf-8")) as DestructiveRules;
  } catch {
    return null;
  }
}

function readStdin(): string {
  try {
    return readFileSync("/dev/stdin", "utf-8");
  } catch {
    return "";
  }
}

export default async function checkDestructive(_args: string[]): Promise<void> {
  try {
    const stdin = readStdin().trim();
    if (!stdin) process.exit(0);

    let toolInput: { tool_name?: string; session_id?: string; agent_id?: string; tool_input?: Record<string, unknown> };
    try {
      toolInput = JSON.parse(stdin);
    } catch {
      process.exit(0);
    }

    const toolName = toolInput.tool_name ?? "";
    const agentId = toolInput.agent_id || toolInput.session_id || process.env.CLAUDE_SESSION_ID || "unknown";
    const command = (toolInput.tool_input?.command as string) ?? "";

    // ── Mudrika identity check (KOS-062) — before any enforcement ─────────
    // Agents registered after Phase 4 always have a mudrika. Agents registered
    // before Phase 4 (no mudrika file) are allowed through — no mudrika file
    // means pre-Phase-4 spawn, not a spoofed identity.
    const mudrika = checkMudrika(agentId);
    if (!mudrika.valid && mudrika.reason !== "no mudrika — agent not registered") {
      process.stderr.write(
        `\n[KAVACH:MUDRIKA] IDENTITY DENIED — ${agentId}: ${mudrika.reason}\n\n`
      );
      process.exit(2);
    }

    // ── Level 0 + Level 1: bitmask enforcement (KAV-YK-014) ──────────────
    const requiredBits = requiredBitsForTool(toolName, command);
    const resourcePath = extractResourceFromToolInput(toolName, toolInput.tool_input ?? {});
    const resourceClassBits = resourcePath ? classifyResource(resourcePath) : 0;

    const valveResult = checkValve(agentId, requiredBits, resourceClassBits);
    incrementLoopCount(agentId);

    if (!valveResult.allowed) {
      const label = valveResult.level === 0 ? "PERM_MASK" : "CLASS_MASK";
      process.stderr.write(
        `\n[KAVACH:L${valveResult.level}] ${label} BLOCK — ${valveResult.reason}\n` +
        `[KAVACH:L${valveResult.level}] Valve state: ${valveResult.valve_state} | Rule: ${valveResult.rule}\n\n`
      );
      process.exit(2);
    }
    // ── End Level 0 + Level 1 ─────────────────────────────────────────────

    // Level 2 only runs for Bash tool (DAN pattern matching)
    if (toolName !== "Bash") process.exit(0);

    const rules = loadRules();
    if (!rules) {
      process.exit(0);
    }

    if (!command) process.exit(0);

    // Override token: human has already confirmed via explicit comment
    if (command.includes(rules.allowed_override_token)) {
      process.stderr.write(`[KAVACH] Override token present — allowing (human confirmed)\n`);
      process.exit(0);
    }

    // Check each rule
    for (const rule of rules.bash_block_patterns) {
      const regex = new RegExp(rule.pattern, rule.flags);
      if (!regex.test(command)) continue;

      if (rule.severity === "CRITICAL") {
        // @rule:KAV-052 — CRITICAL → KAVACH Gate (human approval via WhatsApp + dashboard)
        process.stderr.write(`\n[KAVACH] DANGEROUS ACTION INTERCEPTED — Level ${rule.severity}\n`);
        process.stderr.write(`[KAVACH] Opening approval gate. Check WhatsApp or http://localhost:${DASHBOARD_PORT}\n\n`);

        try {
          const { runKavachGate } = await import("../../kavach/gate");
          const sessionId = toolInput.session_id || process.env.CLAUDE_SESSION_ID || "unknown";
          const result = await runKavachGate(command, "Bash", sessionId);

          if (result.decision === "ALLOW") {
            process.stderr.write(`[KAVACH] ✅ APPROVED — ${result.approval_id} — proceeding\n`);
            process.exit(0);
          }

          if (result.decision === "EXPLAIN") {
            process.stderr.write(`[KAVACH] EXPLAIN requested — context sent. Action blocked pending review.\n`);
            process.stderr.write(`[KAVACH] Approval ID: ${result.approval_id}\n`);
            process.exit(2);
          }

          // STOP or TIMEOUT
          const reason = result.decision === "TIMEOUT" ? "TIMED OUT — default safe block" : "STOPPED by human";
          const msg = buildBlockMessage(rule, result.approval_id, reason);
          process.stderr.write(msg);
          process.exit(2);

        } catch (gateErr: any) {
          // Gate failed internally — default safe = BLOCK
          process.stderr.write(`[KAVACH] Gate error: ${gateErr.message} — blocking by default\n`);
          process.exit(2);
        }

      } else {
        // HIGH/MEDIUM — immediate block with override token info
        const msg = buildBlockMessage(rule, null, rule.reason);
        process.stderr.write(msg);
        process.exit(2);
      }
    }

    process.exit(0);
  } catch {
    process.exit(0); // never block on KAVACH internal errors
  }
}

function buildBlockMessage(
  rule: { severity: string; reason: string; pattern: string },
  approvalId: string | null,
  reason: string
): string {
  return [
    ``,
    `╔══════════════════════════════════════════════════════════════╗`,
    `║  KAVACH BLOCK — DESTRUCTIVE COMMAND INTERCEPTED              ║`,
    `╚══════════════════════════════════════════════════════════════╝`,
    ``,
    `  Severity : ${rule.severity}`,
    `  Reason   : ${reason}`,
    approvalId ? `  Gate ID  : ${approvalId}` : `  Matched  : ${rule.pattern}`,
    ``,
    approvalId
      ? `  To approve: reply ALLOW to WhatsApp or visit http://localhost:${DASHBOARD_PORT}`
      : `  To override: add to command:  # AEGIS-DESTRUCTIVE-CONFIRMED`,
    ``,
  ].join("\n");
}
