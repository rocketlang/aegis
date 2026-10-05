// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// AEGIS Shield — check-shield
// PreToolUse hook for Bash, Read, Write, Edit, and any MCP tool call. It can also be wired
// to PostToolUse, where it reads what a tool sent back (tool_response).
// Exit 0 = allow. Exit 2 = block.
//
// THIS HOOK FAILS OPEN, by design: if the shield itself breaks (input that is not JSON, an
// error inside a check) it exits 0 and the call goes ahead unchecked, so that a fault in
// the guard cannot stop all work. When that happens it says so on stderr. It is the same
// if the harness gives up waiting for the hook: the call goes ahead.
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
  detectBashFiles,
} from "../../shield/injection-detector";
import type { PathContext } from "../../shield/paths";
import { touchAgent, isStopRequested } from "../../core/db";
import { checkMudrika } from "../../kavach/mudrika-validator";
import { checkReachMask, checkBashReachMask } from "../../kavach/reach-mask";
import { recordObservation, extractBashFirstToken, normalizePathPrefix } from "../../sandbox/behavioral-baseline";
import { readValve } from "../../kavach/gate-valve";
import { emitReceipt } from "../../kavach/pramana-emit";
import type { ReceiptVerdict } from "../../../ee/kavach/pramana-receipts";
import { precededByForSession } from "../../shield/provenance";

// Session id for the current hook invocation — captured once, read by emitBlock
// when it records the PRAMANA receipt. Each hook run is its own process.
let _shieldSession = "unknown";
// AF-T-710 — set only for an exfil BLOCK; rides into the receipt context and the banner.
let _precededBy: string | null = null;

function readStdin(): string {
  try {
    // fd 0, not "/dev/stdin": hook stdin is a socket, where /dev/stdin throws ENXIO (blind 09-25→09-29)
    return readFileSync(0, "utf-8");
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
      process.stderr.write("[SHIELD] input was not JSON — this call was NOT checked\n");
      process.exit(0);
    }
    if (toolInput === null || typeof toolInput !== "object" || Array.isArray(toolInput)) {
      process.stderr.write("[SHIELD] input was not a JSON object — this call was NOT checked\n");
      process.exit(0);
    }

    const toolName = (toolInput.tool_name as string) || "";
    const sessionId = (toolInput.session_id as string) || process.env.CLAUDE_SESSION_ID || "unknown";
    const agentId = process.env.CLAUDE_AGENT_ID || sessionId;
    _shieldSession = sessionId;

    // @rule:KOS-062 mudrika identity check before shield scan
    const mudrika = checkMudrika(agentId);
    if (!mudrika.valid && mudrika.reason !== "no mudrika — agent not registered") {
      process.stderr.write(`\n[KAVACH:MUDRIKA] IDENTITY DENIED — ${agentId}: ${mudrika.reason}\n\n`);
      process.exit(2);
    }

    // V2-041 — touch agent in DB (last_seen + tool_calls)
    try { touchAgent(agentId); } catch {}

    // @rule:KAV-088 / KAV-085 — resolve caller perm_mask for reach check + behavioral baseline
    let callerPermMask = 0;
    try { callerPermMask = readValve(agentId).effective_perm_mask; } catch {}

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
    const mcpResult = detectMCPInjection(toolInput, rules);
    if (mcpResult.verdict === "QUARANTINE") {
      emitBlock("SHIELD", mcpResult.rule_id, mcpResult.reason, mcpResult.category, "QUARANTINED");
      process.exit(2);
    }

    // A PostToolUse payload: the tool has already run. The reply was read above; the
    // checks below are about a call that is still to be made.
    if (toolInput.hook_event_name === "PostToolUse") process.exit(0);

    // Tool-specific checks
    const rawInput = toolInput.tool_input;
    const toolInputData = (rawInput && typeof rawInput === "object" && !Array.isArray(rawInput) ? rawInput : {}) as Record<string, unknown>;
    // @rule:KAV-094 — relative paths are resolved against the directory the tool runs in
    const pathCtx: PathContext = { cwd: typeof toolInput.cwd === "string" && toolInput.cwd ? toolInput.cwd : process.cwd() };
    const str = (v: unknown): string => (typeof v === "string" ? v : "");

    if (toolName === "WebFetch") {
      // @rule:KAV-088 reach mask check for cross-service calls
      const url = (toolInputData.url as string) ?? "";
      if (url) {
        const reachResult = checkReachMask(callerPermMask, url);
        if (reachResult.checked && !reachResult.allowed) {
          emitBlock("REACH", "KAV-088", `caller mask 0x${reachResult.caller_mask.toString(16)} lacks bits for ${reachResult.target_service} (required 0x${reachResult.required_mask.toString(16)})`, "reach_mask");
          process.exit(2);
        }
      }
      // @rule:KAV-085 behavioral baseline
      try { recordObservation(agentId, { tool_name: "WebFetch" }); } catch {}

    } else if (toolName === "Read") {
      const filePath = str(toolInputData.file_path);
      if (!filePath) process.exit(0);
      const credResult = detectCredentialRead(filePath, 0, rules, pathCtx);
      if (credResult.verdict === "QUARANTINE") {
        emitBlock("SHIELD", credResult.rule_id, credResult.reason, credResult.category, "QUARANTINED");
        process.exit(2);
      }
      // @rule:KAV-085 behavioral baseline — path prefix observation
      try { recordObservation(agentId, { tool_name: "Read", path_prefix: normalizePathPrefix(filePath) }); } catch {}

    } else if (toolName === "Write" || toolName === "Edit" || toolName === "MultiEdit" || toolName === "NotebookEdit") {
      const filePath = str(toolInputData.file_path) || str(toolInputData.notebook_path);
      if (!filePath) process.exit(0);
      const persResult = detectPersistenceWrite(filePath, rules, pathCtx);
      if (persResult.verdict === "QUARANTINE") {
        emitBlock("SHIELD", persResult.rule_id, persResult.reason, persResult.category, "QUARANTINED");
        process.exit(2);
      }
      // @rule:KAV-085 behavioral baseline
      try { recordObservation(agentId, { tool_name: toolName, path_prefix: normalizePathPrefix(filePath) }); } catch {}

    } else if (toolName === "Bash") {
      const command = str(toolInputData.command);
      if (!command) process.exit(0);

      // @rule:KAV-095 @rule:KAV-096 — the file rules, read off the shell command: a
      // credential file it would read, a persistence target or one of the shield's own
      // files it would write.
      const fileResult = detectBashFiles(command, rules, pathCtx);
      if (fileResult.verdict === "QUARANTINE") {
        emitBlock("SHIELD", fileResult.rule_id, fileResult.reason, fileResult.category, "QUARANTINED");
        process.exit(2);
      }

      // Injection pattern scan
      const scanResult = detectInjection(command, rules);
      if (scanResult.verdict === "QUARANTINE") {
        emitBlock("SHIELD", scanResult.rule_id, scanResult.reason, scanResult.category, "QUARANTINED");
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
        // AF-T-710 — the receipt/banner names what the agent read just before this egress
        try { _precededBy = precededByForSession(sessionId).summary; } catch {}
        // Alert mode lets the command run → the audit verdict must say ALLOWED, not BLOCKED.
        emitBlock("SHIELD", exfilResult.rule_id, exfilResult.reason, exfilResult.category, enforce ? "BLOCKED" : "ALLOWED");
        if (enforce) process.exit(2);
        // Alert mode: warn but allow
        process.stderr.write(`[SHIELD] EXFIL WARNING (${exfilResult.rule_id}): ${exfilResult.reason}\n`);
      }

      // @rule:KAV-088 reach mask check for curl/wget/http calls within bash
      const bashReachResult = checkBashReachMask(callerPermMask, command);
      if (bashReachResult.checked && !bashReachResult.allowed) {
        emitBlock("REACH", "KAV-088", `bash command targets ${bashReachResult.target_service}:${bashReachResult.target_port} — caller mask 0x${bashReachResult.caller_mask.toString(16)} lacks required 0x${bashReachResult.required_mask.toString(16)}`, "reach_mask");
        process.exit(2);
      }

      // @rule:KAV-085 behavioral baseline — bash first-token observation
      const firstToken = extractBashFirstToken(command);
      const behaviorResult = (() => { try { return recordObservation(agentId, { tool_name: "Bash", bash_first_token: firstToken }); } catch { return null; } })();
      if (behaviorResult?.anomaly && enforce) {
        process.stderr.write(`[SHIELD] BEHAVIORAL ANOMALY (KAV-085): ${behaviorResult.reason}\n`);
        // Soft signal — warn in alert mode, request stop in enforce mode
        try { const { requestStop } = require("../../core/db"); requestStop(agentId); } catch {}
      } else if (behaviorResult?.anomaly) {
        process.stderr.write(`[SHIELD] BEHAVIORAL WARN (KAV-085): ${behaviorResult.reason}\n`);
      }

    } else {
      // All other tools — record for baseline
      try { recordObservation(agentId, { tool_name: toolName }); } catch {}
    }

    process.exit(0);
  } catch (err) {
    // Fails OPEN (see the header). Say so: a guard that broke silently looks like a pass.
    try { process.stderr.write(`[SHIELD] internal error — this call was NOT checked (${String((err as Error)?.message ?? err).slice(0, 120)})\n`); } catch {}
    process.exit(0);
  }
}

function emitBlock(source: string, ruleId: string, reason: string, category: string, verdict: ReceiptVerdict = "BLOCKED"): void {
  // @rule:KAV-046 — record the shield decision as a tamper-evident PRAMANA receipt.
  emitReceipt(
    "INJECTION_SHIELD",
    verdict,
    { session_id: _shieldSession, rule_id: ruleId, reason, context: { source, detector_category: category, ...(_precededBy ? { preceded_by: _precededBy } : {}) } },
    {
      rule_applied: ruleId,
      decision_path: `INJECTION_SHIELD -> ${source} -> ${verdict}`,
      human_in_loop: false,
    },
  );
  process.stderr.write([
    ``,
    `╔══════════════════════════════════════════════════════════════╗`,
    // the banner states the ACTUAL verdict — monitor mode lets the action run (AF-T-709)
    `║  AEGIS ${source} — ${verdict}                                       ║`,
    `╚══════════════════════════════════════════════════════════════╝`,
    ``,
    `  Rule     : ${ruleId}`,
    `  Category : ${category}`,
    `  Reason   : ${reason}`,
    ...(_precededBy ? [`  Context  : ${_precededBy}`] : []),
    ``,
    verdict === "ALLOWED"
      ? `  Monitor mode: this action was ALLOWED and recorded by LakshmanRekha (AEGIS Shield).`
      : `  This action was ${verdict.toLowerCase()} by LakshmanRekha (AEGIS Shield).`,
    `  If legitimate, add a named exemption in ~/.aegis/shield-rules.json`,
    ``,
  ].join("\n"));
}
