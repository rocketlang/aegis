// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// KAVACH Gate — check-destructive
// PreToolUse hook for Bash, Write, Edit, Read tools.
// Exit 0 = allow. Exit 2 = block (Claude Code will not execute the tool).
//
// Level 0: (perm_mask & required_bits) !== 0        — O(1), silent block  (KAV-061)
// Level 1: (class_mask & resource_class_bits) !== 0  — O(1), silent block  (KAV-062)
// Level 2: DAN pattern match → block, or the KAVACH Gate (human approval)   (KAV-052)
//
// Two settings decide how much of this runs. Both default to the quieter, safer side, and
// an unreadable config means the defaults — a config fault must not widen what runs.
//
//   kavach.perm_mask_levels    "live"     Levels 0 and 1 run.
//                              (default)  HELD. Only Level 2 runs. Levels 0 and 1 narrow an
//                                         agent's valve after repeated violations, so they are
//                                         switched on deliberately, not by default.
//   kavach.destructive_critical "approve" A CRITICAL match opens the approval gate: a human is
//                                         notified and the call waits for the answer.
//                              (default)  BLOCK. A CRITICAL match is refused at once, like HIGH.
//                                         Nobody is paged and nothing waits.
//
// @rule:KAV-052 — pre-execution intercept for all destructive actions
// @rule:KAV-061 — Level 0 perm_mask enforcement
// @rule:KAV-062 — Level 1 class_mask enforcement
// @rule:KAV-YK-014 — three-level enforcement ordering
// @rule:KAV-098 — nothing typed into the command overrides this gate; an override is a
//                 one-time approval a person gives with `aegis approve-destructive <code>`

import { readFileSync, existsSync } from "fs";
import { join } from "path";
import { DASHBOARD_PORT, loadConfig } from "../../core/config";
import { requiredBitsForTool } from "../../kavach/perm-mask";
import { classifyResource, extractResourceFromToolInput } from "../../kavach/class-mask";
import { checkValve, incrementLoopCount } from "../../kavach/gate-valve";
import { checkMudrika } from "../../kavach/mudrika-validator";
import { destructiveVerdict, type DestructiveRule, type DestructiveRules } from "../../kavach/destructive-verdict";
import { recordRefusal } from "../../core/refusal-ledger";
import { consumeApproval, recordPending } from "../../kavach/destructive-approval";

const AEGIS_DIR = join(process.env.HOME || "/root", ".aegis");
const RULES_PATH = join(AEGIS_DIR, "destructive-rules.json");

/** How a person approves a refused command, spelled for the way this hook was started. */
function approveHint(code: string): string {
  const cli = process.argv[1] && process.argv[1].endsWith(".ts") ? `bun run ${process.argv[1]}` : "aegis";
  return (
    `  To approve THIS command once, a person runs, in their own terminal:\n` +
    `      aegis approve-destructive ${code}\n` +
    (cli === "aegis" ? "" : `      (or: ${cli} approve-destructive ${code})\n`) +
    `  Then run the same command again, unchanged. Nothing added to the command overrides this gate.`
  );
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
    // fd 0, not "/dev/stdin": hook stdin is a socket, where /dev/stdin throws ENXIO
    return readFileSync(0, "utf-8");
  } catch {
    return "";
  }
}

/** The two settings, read so that anything unreadable or unset lands on the default. */
function gateSettings(): { permMaskLive: boolean; criticalApprove: boolean } {
  try {
    const k = (loadConfig().kavach ?? {}) as Record<string, unknown>;
    return { permMaskLive: k.perm_mask_levels === "live", criticalApprove: k.destructive_critical === "approve" };
  } catch {
    return { permMaskLive: false, criticalApprove: false };
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
      // @rule:ANU-004 — input this gate cannot read is a command it cannot judge. (Until
      // 2.5.0 this case alone was allowed, the opposite of the gate's own rule.)
      process.stderr.write(`\n[KAVACH] REFUSED — the hook input was not JSON, so this gate cannot judge the call (ANU-004).\n\n`);
      process.exit(2);
    }
    if (toolInput === null || typeof toolInput !== "object" || Array.isArray(toolInput)) {
      process.stderr.write(`\n[KAVACH] REFUSED — the hook input was not a JSON object, so this gate cannot judge the call (ANU-004).\n\n`);
      process.exit(2);
    }

    const toolName = toolInput.tool_name ?? "";
    const agentId = toolInput.agent_id || toolInput.session_id || process.env.CLAUDE_SESSION_ID || "unknown";
    const rawCommand = (toolInput.tool_input as Record<string, unknown> | undefined)?.command;
    const command = typeof rawCommand === "string" ? rawCommand : "";
    const settings = gateSettings();

    if (settings.permMaskLive) {
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
    }

    // Level 2 only runs for Bash tool (DAN pattern matching)
    if (toolName !== "Bash") process.exit(0);

    const rules = loadRules();
    if (!rules) {
      // @rule:ANU-004 — the rules file IS the state this gate depends on. Unreadable state
      // refuses; it does not wave every Bash command through. Marine interlocks fail safe.
      // The override token is duplicated as a constant precisely so the escape hatch does
      // not itself depend on the file that just failed to load.
      if (!command) process.exit(0); // nothing to judge is not unknown state
      process.stderr.write(
        `\n[KAVACH] REFUSED — destructive-rules are unreadable, so this gate cannot judge the command.\n` +
          `[KAVACH] Expected: ${RULES_PATH}\n` +
          `[KAVACH] A gate that cannot read its own rules must refuse, not allow (ANU-004).\n` +
          `[KAVACH] A person restores the file: \`aegis init\` puts the shipped rules there if none exist.\n\n`,
      );
      process.exit(2);
    }

    if (!command) process.exit(0);

    // The decision is pure and shared with the red-team harness (destructive-verdict.ts);
    // everything below is the side effect of that decision.
    const verdict = destructiveVerdict(command, rules);

    // @rule:KAV-098 — a person approved this exact command with `aegis approve-destructive`.
    // The approval is used up here, and its use is recorded: an override nobody can count
    // is indistinguishable from a gate that never fired.
    if (verdict.kind === "match" && consumeApproval(command)) {
      recordRefusal({ gate: "aegis-destructive", kind: "override", rule: "KAV-098" });
      process.stderr.write(`[KAVACH] One-time approval found for this exact command — allowing, once\n`);
      process.exit(0);
    }

    // A destructive keyword that is only DISPLAYED (bare echo/printf/comment, no execution
    // path) reaches no interpreter — allow it, but say so, so a suppressed match is visible.
    if (verdict.kind === "inert") {
      process.stderr.write(
        `[KAVACH] '${verdict.wouldMatch.pattern}' appears only as displayed text (no execution path) — allowing\n`,
      );
      process.exit(0);
    }

    if (verdict.kind === "match") {
      const rule = verdict.rule;

      if (rule.severity === "CRITICAL" && settings.criticalApprove) {
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
          const msg = buildBlockMessage(rule, result.approval_id, reason, null);
          process.stderr.write(msg);
          process.exit(2);

        } catch (gateErr: any) {
          // Gate failed internally — default safe = BLOCK
          process.stderr.write(`[KAVACH] Gate error: ${gateErr.message} — blocking by default\n`);
          process.exit(2);
        }

      } else {
        // HIGH/MEDIUM, and CRITICAL unless the approval gate is switched on — immediate block.
        const msg = buildBlockMessage(rule, null, rule.reason, recordPending(command, rule.pattern));
        process.stderr.write(msg);
        process.exit(2);
      }
    }

    process.exit(0);
  } catch (err: any) {
    // @rule:ANU-004 — an internal failure means this gate does not know whether the command
    // is safe. Not knowing refuses. The inner gate-error handler twelve lines above has
    // always done exactly this ("default safe = BLOCK"); the outer catch used to do the
    // opposite, which meant any KAVACH bug silently disarmed the whole gate.
    process.stderr.write(
      `\n[KAVACH] REFUSED — gate failed internally: ${err?.message ?? "unknown error"}\n` +
        `[KAVACH] A gate that cannot judge must refuse, not allow (ANU-004).\n\n`,
    );
    process.exit(2);
  }
}

function buildBlockMessage(
  rule: { severity: string; reason: string; pattern: string },
  approvalId: string | null,
  reason: string,
  code: string | null,
): string {
  return [
    ``,
    `╔══════════════════════════════════════════════════════════════╗`,
    `║  KAVACH BLOCK — DESTRUCTIVE COMMAND INTERCEPTED              ║`,
    `╚══════════════════════════════════════════════════════════════╝`,
    ``,
    `  Rule     : KAV-052`,
    `  Severity : ${rule.severity}`,
    `  Reason   : ${reason}`,
    approvalId ? `  Gate ID  : ${approvalId}` : `  Matched  : ${rule.pattern}`,
    ``,
    approvalId
      ? `  To approve: reply ALLOW to WhatsApp or visit http://localhost:${DASHBOARD_PORT}`
      : code ? approveHint(code) : `  This command was refused.`,
    ``,
  ].join("\n");
}
