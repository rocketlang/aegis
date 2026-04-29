// AEGIS Sandbox — Policy Loader + Agent Identity Resolver
// @rule:KAV-011 Agent identity resolution
// @rule:KAV-YK-008 Identity confidence → enforcement threshold mapping

import { existsSync, readFileSync } from "fs";
import { join } from "path";
import { createHash } from "crypto";
import { getAegisDir } from "../core/config";
import { validatePolicy, makeDefaultPolicy, type AgentPolicy } from "./policy-schema";

// ────────────────────────────────────────────────────────────
// Identity confidence levels (KAV-YK-008)
// ────────────────────────────────────────────────────────────

export type IdentityConfidence = "declared" | "convention" | "fingerprint" | "unknown";

// Enforcement threshold per confidence level:
// declared    → full enforcement (block on any violation)
// convention  → full enforcement (policy file exists, name from convention)
// fingerprint → soft enforcement (WARN instead of BLOCK for first violation)
// unknown     → minimal enforcement (WARN only, no QUARANTINE)
export const ENFORCEMENT_THRESHOLD: Record<IdentityConfidence, "full" | "soft" | "warn_only"> = {
  declared: "full",
  convention: "full",
  fingerprint: "soft",
  unknown: "warn_only",
};

export interface ResolvedIdentity {
  agent_id: string;
  confidence: IdentityConfidence;
  source: string;
}

// ────────────────────────────────────────────────────────────
// Three-level identity resolver (KAV-011)
// ────────────────────────────────────────────────────────────

export function resolveAgentId(opts: {
  envAgentId?: string;           // AEGIS_AGENT_ID env var
  systemPromptText?: string;     // first N chars of system prompt
  spawnTimestamp?: number;       // ms since epoch, for fingerprint
  stdinJson?: Record<string, unknown>; // parsed tool input for prompt extraction
}): ResolvedIdentity {
  // Level 1 — declared via env var (most confident)
  const fromEnv = opts.envAgentId ?? process.env.AEGIS_AGENT_ID;
  if (fromEnv && fromEnv.trim()) {
    return { agent_id: fromEnv.trim(), confidence: "declared", source: "AEGIS_AGENT_ID env var" };
  }

  // Level 2 — convention magic line in system prompt
  // Claude Code injects system prompts into stdin JSON for some hooks
  const promptText = opts.systemPromptText ?? extractPromptFromStdin(opts.stdinJson);
  if (promptText) {
    const match = promptText.match(/^#\s*KAVACH-AGENT:\s*(.+)$/m);
    if (match) {
      return { agent_id: match[1].trim(), confidence: "convention", source: "KAVACH-AGENT magic line in system prompt" };
    }
  }

  // Level 3 — SHA-256 fingerprint of system prompt + spawn timestamp
  if (promptText) {
    const ts = opts.spawnTimestamp ?? Date.now();
    const hash = createHash("sha256").update(`${promptText}:${ts}`).digest("hex").slice(0, 16);
    return { agent_id: `fp-${hash}`, confidence: "fingerprint", source: "SHA-256 fingerprint of system prompt + timestamp" };
  }

  // Level 4 — no identity possible
  const sessionId = process.env.CLAUDE_SESSION_ID || "unknown";
  return { agent_id: `unknown-${sessionId}`, confidence: "unknown", source: "no identity signal found" };
}

function extractPromptFromStdin(stdin?: Record<string, unknown>): string | null {
  if (!stdin) return null;
  // Claude Code PreToolUse JSON may contain a "system_prompt" key or it may be nested
  const sp = (stdin as any)?.system_prompt ?? (stdin as any)?.tool_input?.system_prompt;
  return typeof sp === "string" ? sp : null;
}

// ────────────────────────────────────────────────────────────
// Policy loader with per-process cache
// ────────────────────────────────────────────────────────────

const _policyCache: Map<string, AgentPolicy> = new Map();

export function loadPolicy(agentId: string): AgentPolicy | null {
  if (_policyCache.has(agentId)) return _policyCache.get(agentId)!;

  const policyPath = join(getAegisDir(), "agents", `${agentId}.json`);
  if (!existsSync(policyPath)) return null;

  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(policyPath, "utf-8"));
  } catch {
    return null;
  }

  const validation = validatePolicy(raw);
  if (!validation.valid) {
    process.stderr.write(`[AEGIS] Policy file invalid for ${agentId}: ${validation.errors.join(", ")}\n`);
    return null;
  }

  const policy = raw as AgentPolicy;
  _policyCache.set(agentId, policy);
  return policy;
}

export function clearPolicyCache(): void {
  _policyCache.clear();
}

// Load policy or fall back to default (open policy) for unknown agents
export function loadPolicyOrDefault(identity: ResolvedIdentity): AgentPolicy {
  const policy = loadPolicy(identity.agent_id);
  if (policy) return policy;
  return makeDefaultPolicy(identity.agent_id);
}
