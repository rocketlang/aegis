// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// AEGIS Quarantine — list + release (V2-033, V2-034)
// aegis quarantine list          — show all QUARANTINED/ORPHAN agents
// aegis quarantine release <id>  — human-in-the-loop release from quarantine
// @rule:KAV-004 Quarantine state and human release
// @rule:KAV-012 Orphan detection
// @rule:KAV-YK-005 Escalation → quarantine transition

import { loadAgent, listAgents, transitionState, type AgentRecord } from "../../sandbox/quarantine";
import { readFileSync, existsSync } from "fs";
import { join } from "path";
import { getAegisDir } from "../../core/config";

function loadRingBuffer(agentId: string): string[] {
  const violationsPath = join(getAegisDir(), "violations", `${agentId}.jsonl`);
  if (!existsSync(violationsPath)) return [];
  try {
    return readFileSync(violationsPath, "utf-8")
      .trim()
      .split("\n")
      .filter(Boolean)
      .slice(-5);  // last 5 violations
  } catch {
    return [];
  }
}

function renderAgent(rec: AgentRecord, verbose: boolean): void {
  const age = Math.round((Date.now() - new Date(rec.spawn_timestamp).getTime()) / 1000);
  const stateColor = rec.state === "QUARANTINED" ? "\x1b[31m" : "\x1b[33m";
  const reset = "\x1b[0m";

  console.log(`  ${stateColor}[${rec.state}]${reset} ${rec.agent_id}`);
  console.log(`    Confidence: ${rec.identity_confidence}  Depth: ${rec.depth}  Age: ${age}s`);
  console.log(`    Violations: ${rec.violation_count}  Tool calls: ${rec.tool_calls}`);
  if (rec.quarantine_reason) {
    console.log(`    Reason:     ${rec.quarantine_reason} (${rec.quarantine_rule ?? "no rule"})`);
  }
  if (rec.parent_id) {
    console.log(`    Parent:     ${rec.parent_id}`);
  }

  if (verbose) {
    const ring = loadRingBuffer(rec.agent_id);
    if (ring.length > 0) {
      console.log("    Violation ring buffer (last 5):");
      for (const line of ring) {
        try {
          const v = JSON.parse(line);
          console.log(`      [${v.severity}] ${v.pattern} — ${v.tool}:${v.input?.slice(0, 60) ?? ""}`);
        } catch {
          console.log(`      ${line.slice(0, 80)}`);
        }
      }
    }
  }
  console.log();
}

function listQuarantined(args: string[]): void {
  const verbose = args.includes("--verbose") || args.includes("-v");
  const agents = listAgents(["QUARANTINED", "ORPHAN"]);

  if (agents.length === 0) {
    console.log("[AEGIS] No agents in QUARANTINE or ORPHAN state.");
    return;
  }

  const quarantined = agents.filter((a) => a.state === "QUARANTINED");
  const orphaned    = agents.filter((a) => a.state === "ORPHAN");

  console.log(`\x1b[1m[AEGIS] Quarantine Report\x1b[0m — ${agents.length} agent(s) require attention\n`);

  if (quarantined.length > 0) {
    console.log(`\x1b[31mQUARANTINED (${quarantined.length})\x1b[0m — blocked, awaiting human release`);
    console.log("─".repeat(60));
    for (const rec of quarantined) renderAgent(rec, verbose);
  }

  if (orphaned.length > 0) {
    console.log(`\x1b[33mORPHAN (${orphaned.length})\x1b[0m — parent gone, no heartbeat`);
    console.log("─".repeat(60));
    for (const rec of orphaned) renderAgent(rec, verbose);
  }

  console.log(`To release: \x1b[36maegis quarantine release <agent-id> --reason "..."\x1b[0m`);
}

function releaseQuarantined(subargs: string[]): void {
  const agentId = subargs[0];
  if (!agentId || agentId.startsWith("--")) {
    console.error("[AEGIS] quarantine release: agent-id required");
    console.error("  Usage: aegis quarantine release <agent-id> --reason \"<reason>\"");
    process.exit(1);
  }

  const idxReason = subargs.indexOf("--reason");
  const reason    = idxReason >= 0 ? subargs[idxReason + 1] : "";
  const idxBy     = subargs.indexOf("--by");
  const releasedBy = idxBy >= 0 ? subargs[idxBy + 1] : (process.env.USER ?? "operator");

  if (!reason) {
    console.error("[AEGIS] quarantine release: --reason is required (human-in-the-loop — must document why)");
    console.error("  Example: aegis quarantine release <id> --reason \"false positive — reviewed ring buffer, no exfil\"");
    process.exit(1);
  }

  const record = loadAgent(agentId);
  if (!record) {
    console.error(`[AEGIS] quarantine release: agent ${agentId} not found`);
    process.exit(1);
  }

  if (record.state !== "QUARANTINED") {
    console.error(`[AEGIS] quarantine release: agent is in state ${record.state}, not QUARANTINED`);
    process.exit(1);
  }

  const result = transitionState(agentId, "RUNNING", {
    reason,
    released_by: releasedBy,
  });

  if (!result.success) {
    console.error(`[AEGIS] quarantine release failed: ${result.error}`);
    process.exit(1);
  }

  console.log(`\x1b[32m[AEGIS] Released:\x1b[0m ${agentId}`);
  console.log(`  State:       QUARANTINED → RUNNING`);
  console.log(`  Released by: ${releasedBy}`);
  console.log(`  Reason:      ${reason}`);
  console.log(`  Prior violations: ${record.violation_count}`);
  console.log(`\n  Agent may resume tool calls. Monitor for repeat violations.`);
}

export default function quarantine(args: string[]): void {
  const subcommand = args[0] ?? "list";
  const subargs = args.slice(1);

  switch (subcommand) {
    case "list":
      return listQuarantined(subargs);
    case "release":
      return releaseQuarantined(subargs);
    default:
      console.error(`[AEGIS] quarantine: unknown subcommand "${subcommand}"`);
      console.error("  Usage:");
      console.error("    aegis quarantine list [--verbose]");
      console.error("    aegis quarantine release <agent-id> --reason \"...\" [--by <name>]");
      process.exit(1);
  }
}
