// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// AEGIS Cost — cost attribution tree for current session (V2-067)
// @rule:KAV-009 Projected cost alerts
// @rule:KAV-017 Per-agent cost attribution
// @rule:KAV-003 Budget pool tree

import { getCostTree, listAgentRows, getAgentCostProjection, type CostTreeNode } from "../../core/db";

function formatUsd(v: number): string {
  return `$${v.toFixed(4)}`;
}

function renderNode(node: CostTreeNode, indent = 0): string[] {
  const lines: string[] = [];
  const pad = "  ".repeat(indent);
  const stateIcon: Record<string, string> = {
    RUNNING: "🟢",
    QUARANTINED: "🔴",
    COMPLETED: "✅",
    ZOMBIE: "💀",
    ORPHAN: "👻",
    FORCE_CLOSED: "🔒",
    KILLED: "❌",
  };
  const icon = stateIcon[node.state] ?? "⚪";

  const pctUsed = node.budget_cap_usd > 0 ? (node.budget_used_usd / node.budget_cap_usd) * 100 : 0;
  const budgetStr = node.budget_cap_usd > 0
    ? `${formatUsd(node.budget_used_usd)}/${formatUsd(node.budget_cap_usd)} (${pctUsed.toFixed(0)}%)`
    : formatUsd(node.budget_used_usd);

  const reservedStr = node.budget_pool_reserved > 0 ? ` [reserved: ${formatUsd(node.budget_pool_reserved)}]` : "";
  const violStr = node.violation_count > 0 ? ` ⚠️ ${node.violation_count} violations` : "";

  lines.push(`${pad}${icon} ${node.agent_id} [depth=${node.depth}]`);
  lines.push(`${pad}   cost: ${budgetStr}${reservedStr}  calls: ${node.tool_calls}${violStr}`);

  // Overspend warning
  if (pctUsed > 80) {
    lines.push(`${pad}   ⚠️  ${pctUsed.toFixed(0)}% of cap used`);
  }

  for (const child of node.children) {
    lines.push(...renderNode(child, indent + 1));
  }

  return lines;
}

export default function cost(args: string[]): void {
  const sessionId = args[0] || undefined;
  const tree = getCostTree(sessionId);

  if (tree.length === 0) {
    const allAgents = listAgentRows();
    if (allAgents.length === 0) {
      console.log("[AEGIS] No agents registered. Use: aegis register --id <id>");
    } else {
      console.log(`[AEGIS] ${allAgents.length} agents in registry but no active tree. Run without --session to see all.`);
    }
    process.exit(0);
  }

  // Compute totals
  let totalUsed = 0;
  let totalCap = 0;
  let totalCalls = 0;
  function sumTree(nodes: CostTreeNode[]): void {
    for (const n of nodes) {
      totalUsed += n.budget_used_usd;
      totalCap += n.budget_cap_usd;
      totalCalls += n.tool_calls;
      sumTree(n.children);
    }
  }
  sumTree(tree);

  const lines = [
    ``,
    `╔══════════════════════════════════════════════════════════════╗`,
    `║  AEGIS Cost Attribution Tree                                 ║`,
    `╚══════════════════════════════════════════════════════════════╝`,
    ``,
  ];

  if (sessionId) lines.push(`  Session: ${sessionId}`);
  lines.push(`  Total cost: ${formatUsd(totalUsed)} across ${totalCalls} tool calls`);
  if (totalCap > 0) lines.push(`  Total cap:  ${formatUsd(totalCap)}`);
  lines.push(``);

  for (const root of tree) {
    lines.push(...renderNode(root));
    lines.push(``);
  }

  // Risk flags
  const running = listAgentRows(["RUNNING"]);
  const atRisk = running.filter((a) => {
    const proj = getAgentCostProjection(a.agent_id);
    return proj && proj.alert_level !== "ok";
  });

  if (atRisk.length > 0) {
    lines.push(`  ⚠️  At-risk agents (projected overspend):`);
    for (const a of atRisk) {
      const proj = getAgentCostProjection(a.agent_id)!;
      lines.push(`     ${a.agent_id}: ${proj.pct_of_cap.toFixed(0)}% of cap (${proj.alert_level.toUpperCase()})`);
    }
    lines.push(``);
  }

  process.stdout.write(lines.join("\n") + "\n");
}
