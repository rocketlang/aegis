// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// AEGIS Resume Manifest Writer (V2-049)
// Constructs a resume manifest from the agent's ring buffer of tool calls.
// Written to ~/.aegis/manifests/{agent_id}.manifest.json
// @rule:KAV-010 Resume manifest captures session state for graceful continuation
// @rule:KAV-YK-006 Manifest content: completed/in_progress/pending steps + files + resume_prompt

import { existsSync, writeFileSync, readFileSync, mkdirSync } from "fs";
import { join } from "path";
import { getAegisDir } from "../core/config";
import type { AgentRow } from "../core/db";

export interface ResumeManifest {
  agent_id: string;
  session_id: string;
  created_at: string;
  trigger: string;            // "zombie_timeout" | "orphan_ttl" | "soft_stop" | "manual"
  state_at_capture: string;
  tool_calls_total: number;
  loop_count: number;
  violation_count: number;
  budget_used_usd: number;
  // These are populated if ring buffer state is available
  completed_steps: string[];
  in_progress_steps: string[];
  pending_steps: string[];
  files_modified: string[];
  files_partial: string[];
  dbs_touched: string[];
  git_state: string;
  resume_prompt: string;
}

function getManifestsDir(): string {
  const dir = join(getAegisDir(), "manifests");
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  return dir;
}

function loadRingBuffer(agentId: string): string[] {
  // Ring buffer is stored in the violation log file
  const path = join(getAegisDir(), "agents", `${agentId}.violations.jsonl`);
  if (!existsSync(path)) return [];
  try {
    return readFileSync(path, "utf-8")
      .trim()
      .split("\n")
      .filter(Boolean)
      .map((line) => {
        try { return JSON.parse(line).message ?? line; } catch { return line; }
      });
  } catch {
    return [];
  }
}

export async function writeManifest(agent: AgentRow, trigger: string): Promise<string> {
  const ringBuffer = loadRingBuffer(agent.agent_id);

  const manifest: ResumeManifest = {
    agent_id: agent.agent_id,
    session_id: agent.session_id,
    created_at: new Date().toISOString(),
    trigger,
    state_at_capture: agent.state,
    tool_calls_total: agent.tool_calls,
    loop_count: agent.loop_count,
    violation_count: agent.violation_count,
    budget_used_usd: agent.budget_used_usd,
    completed_steps: ringBuffer.filter((l) => l.includes("completed") || l.includes("COMPLETED")),
    in_progress_steps: ringBuffer.filter((l) => l.includes("in_progress") || l.includes("partial")),
    pending_steps: [],
    files_modified: ringBuffer
      .filter((l) => l.includes("Write") || l.includes("Edit"))
      .map((l) => l.replace(/^.*?: /, "")),
    files_partial: [],
    dbs_touched: ringBuffer.filter((l) => l.includes("prisma") || l.includes("psql") || l.includes(".db")),
    git_state: "unknown — run `git status` to verify",
    resume_prompt: buildResumePrompt(agent, ringBuffer),
  };

  const path = join(getManifestsDir(), `${agent.agent_id}.manifest.json`);
  writeFileSync(path, JSON.stringify(manifest, null, 2));
  return path;
}

function buildResumePrompt(agent: AgentRow, ringBuffer: string[]): string {
  const lastActions = ringBuffer.slice(-5).join("; ");
  return [
    `AEGIS RESUME CONTEXT for agent ${agent.agent_id}:`,
    `Session: ${agent.session_id}`,
    `Stopped: ${agent.state} (${agent.tool_calls} tool calls, ${agent.violation_count} violations, $${agent.budget_used_usd.toFixed(4)} used)`,
    `Last known actions: ${lastActions || "none recorded"}`,
    ``,
    `To resume this work: read the full manifest, check git status, then continue from the last in-progress step.`,
    `Run \`aegis resume ${agent.agent_id}\` to display the full manifest.`,
  ].join("\n");
}
