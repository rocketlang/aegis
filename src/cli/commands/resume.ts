// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// AEGIS Resume — display resume manifest for a force-closed agent (V2-050)
// @rule:KAV-010 Resume manifest captures session state for graceful continuation
// @rule:KAV-YK-006 resume_prompt is for direct paste into a new agent session

import { existsSync, readFileSync } from "fs";
import { join } from "path";
import { getAegisDir } from "../../core/config";
import { getAgentRow } from "../../core/db";
import type { ResumeManifest } from "../../watchdog/manifest-writer";

export default function resume(args: string[]): void {
  const agentId = args[0];
  if (!agentId) {
    console.error("[AEGIS] resume: agent_id required — usage: aegis resume <agent-id>");
    process.exit(1);
  }

  const manifestPath = join(getAegisDir(), "manifests", `${agentId}.manifest.json`);

  // Also check if the agent record has a path
  let path = manifestPath;
  const dbRow = getAgentRow(agentId);
  if (dbRow?.resume_manifest_path && existsSync(dbRow.resume_manifest_path)) {
    path = dbRow.resume_manifest_path;
  }

  if (!existsSync(path)) {
    console.error(`[AEGIS] No resume manifest found for agent: ${agentId}`);
    console.error(`  Expected: ${path}`);
    console.error(`  The agent may not have been force-closed yet, or the manifest was not written.`);
    process.exit(1);
  }

  let manifest: ResumeManifest;
  try {
    manifest = JSON.parse(readFileSync(path, "utf-8")) as ResumeManifest;
  } catch {
    console.error(`[AEGIS] Failed to read manifest: ${path}`);
    process.exit(1);
  }

  const lines = [
    ``,
    `╔══════════════════════════════════════════════════════════════╗`,
    `║  AEGIS Resume Manifest                                       ║`,
    `╚══════════════════════════════════════════════════════════════╝`,
    ``,
    `  Agent     : ${manifest.agent_id}`,
    `  Session   : ${manifest.session_id}`,
    `  Created   : ${manifest.created_at}`,
    `  Trigger   : ${manifest.trigger}`,
    `  State     : ${manifest.state_at_capture}`,
    `  Tool calls: ${manifest.tool_calls_total}  |  Violations: ${manifest.violation_count}  |  Cost: $${manifest.budget_used_usd.toFixed(4)}`,
    ``,
  ];

  if (manifest.completed_steps.length > 0) {
    lines.push(`  ✅ Completed steps (${manifest.completed_steps.length}):`);
    manifest.completed_steps.forEach((s) => lines.push(`     ${s}`));
    lines.push(``);
  }

  if (manifest.in_progress_steps.length > 0) {
    lines.push(`  🔶 In-progress steps (${manifest.in_progress_steps.length}):`);
    manifest.in_progress_steps.forEach((s) => lines.push(`     ${s}`));
    lines.push(``);
  }

  if (manifest.pending_steps.length > 0) {
    lines.push(`  ⏳ Pending steps (${manifest.pending_steps.length}):`);
    manifest.pending_steps.forEach((s) => lines.push(`     ${s}`));
    lines.push(``);
  }

  if (manifest.files_modified.length > 0) {
    lines.push(`  📝 Files modified:`);
    manifest.files_modified.slice(0, 20).forEach((f) => lines.push(`     ${f}`));
    if (manifest.files_modified.length > 20) lines.push(`     ... (${manifest.files_modified.length - 20} more)`);
    lines.push(``);
  }

  if (manifest.dbs_touched.length > 0) {
    lines.push(`  🗄️  Databases touched:`);
    manifest.dbs_touched.forEach((d) => lines.push(`     ${d}`));
    lines.push(``);
  }

  lines.push(`  Git state : ${manifest.git_state}`);
  lines.push(``);
  lines.push(`  ─── Resume prompt (paste into new agent session) ───────────────`);
  lines.push(``);
  manifest.resume_prompt.split("\n").forEach((l) => lines.push(`  ${l}`));
  lines.push(``);
  lines.push(`  Manifest file: ${path}`);
  lines.push(``);

  process.stdout.write(lines.join("\n"));
}
