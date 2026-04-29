// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// AEGIS Monitor — JSONL Parser
// Parses session log lines from ANY agentic tool that writes JSONL with usage data
// Currently supports: Claude Code, extensible to Codex/Cursor/AnvilOS/TraitOS

import type { UsageRecord } from "../core/types";
import { estimateCostUsd } from "../core/pricing";
import { loadConfig } from "../core/config";

export interface ParsedLine {
  usage: UsageRecord | null;
  is_user_message: boolean;
  session_id: string | null;
}

// Provider detection — AEGIS is vendor-neutral
type Provider = "claude-code" | "openai-codex" | "cursor" | "ankr-anvilos" | "ankr-traitos" | "generic";

function detectProvider(data: any): Provider {
  if (data.entrypoint === "cli" && data.version && data.slug) return "claude-code";
  // Codex CLI: rollout files have event_msg/session_meta types with payload.type structure
  if (data.type === "event_msg" || data.type === "session_meta" || data.type === "response_item") return "openai-codex";
  if (data.payload?.originator?.includes("codex") || data.payload?.originator === "codex_exec") return "openai-codex";
  if (data.provider === "openai" || data.model?.startsWith("gpt-") || data.model?.startsWith("o3") || data.model?.startsWith("codex")) return "openai-codex";
  if (data.source === "cursor" || data.provider === "cursor") return "cursor";
  if (data.source === "anvilos" || data.provider === "anvilos") return "ankr-anvilos";
  if (data.source === "traitos" || data.provider === "traitos") return "ankr-traitos";
  return "generic";
}

// Extract usage from Claude Code JSONL format
function parseClaudeCode(data: any, projectPath: string): ParsedLine {
  const session_id = data.sessionId || data.message?.sessionId || null;
  const is_user = data.type === "user" || data.message?.role === "user";

  if (data.type !== "assistant" && data.message?.role !== "assistant") {
    return { usage: null, is_user_message: is_user, session_id };
  }

  const usage = data.message?.usage;
  if (!usage) return { usage: null, is_user_message: false, session_id };

  const model = data.message?.model || "unknown";
  const config = loadConfig();

  // Detect agent spawns by checking for Agent tool use
  let is_agent_spawn = false;
  const content = data.message?.content;
  if (Array.isArray(content)) {
    is_agent_spawn = content.some((c: any) => c.type === "tool_use" && c.name === "Agent");
  }

  const cost = estimateCostUsd(
    model,
    usage.input_tokens || 0,
    usage.output_tokens || 0,
    usage.cache_read_input_tokens || 0,
    usage.cache_creation_input_tokens || 0,
    config.pricing_mode,
    config.max_plan_discount
  );

  return {
    usage: {
      session_id: session_id || "unknown",
      timestamp: data.timestamp || new Date().toISOString(),
      model,
      input_tokens: usage.input_tokens || 0,
      output_tokens: usage.output_tokens || 0,
      cache_read_tokens: usage.cache_read_input_tokens || 0,
      cache_creation_tokens: usage.cache_creation_input_tokens || 0,
      estimated_cost_usd: cost,
      is_agent_spawn,
    },
    is_user_message: false,
    session_id,
  };
}

// Extract usage from OpenAI Codex CLI format
// Codex writes to ~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl
// Format: { timestamp, type: "event_msg", payload: { type: "token_count", info: { last_token_usage: {...} } } }
function parseOpenAI(data: any, projectPath: string): ParsedLine {
  // Codex session_meta line has id and model
  if (data.type === "session_meta") {
    const sid = data.payload?.id || null;
    return { usage: null, is_user_message: false, session_id: sid };
  }

  // Codex user_message line = user activity
  if (data.type === "user_message" || data.payload?.type === "user_message") {
    return { usage: null, is_user_message: true, session_id: data.payload?.session_id || null };
  }

  // Codex token_count event
  if (data.type === "event_msg" && data.payload?.type === "token_count") {
    const info = data.payload.info;
    if (!info || !info.last_token_usage) {
      return { usage: null, is_user_message: false, session_id: null };
    }

    const usage = info.last_token_usage;
    const session_id = extractCodexSessionId(projectPath) || "codex-unknown";
    const model = data.payload.model || "gpt-5-codex";

    // OpenAI pricing approximations (as of 2026)
    const inputPrice = model.includes("o1") ? 15 : model.includes("o3") ? 10 : 2.50;
    const outputPrice = model.includes("o1") ? 60 : model.includes("o3") ? 40 : 10;
    const cachedPrice = inputPrice / 2;

    const cost =
      ((usage.input_tokens || 0) / 1_000_000) * inputPrice +
      ((usage.cached_input_tokens || 0) / 1_000_000) * cachedPrice +
      ((usage.output_tokens || 0) / 1_000_000) * outputPrice +
      ((usage.reasoning_output_tokens || 0) / 1_000_000) * outputPrice;

    return {
      usage: {
        session_id,
        timestamp: data.timestamp || new Date().toISOString(),
        model,
        input_tokens: (usage.input_tokens || 0) - (usage.cached_input_tokens || 0),
        output_tokens: (usage.output_tokens || 0) + (usage.reasoning_output_tokens || 0),
        cache_read_tokens: usage.cached_input_tokens || 0,
        cache_creation_tokens: 0,
        estimated_cost_usd: cost,
        is_agent_spawn: false,
      },
      is_user_message: false,
      session_id,
    };
  }

  // Legacy / generic OpenAI format (direct API response)
  const session_id = data.session_id || data.id || null;
  const usage = data.usage;
  if (!usage) return { usage: null, is_user_message: false, session_id };

  const model = data.model || "unknown";
  const cost =
    ((usage.prompt_tokens || 0) / 1_000_000) * 2.5 +
    ((usage.completion_tokens || 0) / 1_000_000) * 10;

  return {
    usage: {
      session_id: session_id || "unknown",
      timestamp: data.created ? new Date(data.created * 1000).toISOString() : new Date().toISOString(),
      model,
      input_tokens: usage.prompt_tokens || 0,
      output_tokens: usage.completion_tokens || 0,
      cache_read_tokens: 0,
      cache_creation_tokens: 0,
      estimated_cost_usd: cost,
      is_agent_spawn: false,
    },
    is_user_message: false,
    session_id,
  };
}

// Extract Codex session ID from file path
// /root/.codex/sessions/2026/01/16/rollout-2026-01-16T10-41-42-019bc537-6da6-76e1-847d-cbaaa61fccd6.jsonl
function extractCodexSessionId(path: string): string | null {
  const match = path.match(/rollout-[\d\-T]+-([0-9a-f\-]+)\.jsonl/);
  return match ? `codex-${match[1].slice(0, 8)}` : null;
}

// Main parse function — auto-detects provider and extracts usage
export function parseLine(line: string, projectPath: string): ParsedLine {
  if (!line.trim() || !line.startsWith("{")) {
    return { usage: null, is_user_message: false, session_id: null };
  }

  try {
    const data = JSON.parse(line);
    const provider = detectProvider(data);

    switch (provider) {
      case "claude-code":
        return parseClaudeCode(data, projectPath);
      case "openai-codex":
      case "cursor":
        return parseOpenAI(data, projectPath);
      case "ankr-anvilos":
      case "ankr-traitos":
        // ANKR agents use the same JSONL format as Claude Code (they run on Claude)
        return parseClaudeCode(data, projectPath);
      default:
        // Generic: try Claude format first, then OpenAI
        const claude = parseClaudeCode(data, projectPath);
        if (claude.usage) return claude;
        return parseOpenAI(data, projectPath);
    }
  } catch {
    return { usage: null, is_user_message: false, session_id: null };
  }
}
