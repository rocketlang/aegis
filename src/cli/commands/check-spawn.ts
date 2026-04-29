// AEGIS Hook — check-spawn
// Called by Claude Code PreToolUse hook when Agent tool is invoked.
// Default mode (alert): warns but never blocks.
// Enforce mode: blocks when spawn limit reached.
// Also runs HanumanG 7-axis check on the agent being spawned.
//
// Level 0: SPAWN_AGENTS perm_mask bit check (KAV-061)
// Phase 1b: MVT surface check (KAV-067), loop escalation (KAV-068), INF-KAV-012 tightening
// @rule:KAV-015 HanumanG delegation chain validation
// @rule:KAV-061 Level 0 perm_mask enforcement — SPAWN_AGENTS bit
// @rule:KAV-067 Minimum Viable Toolset — warn when tools_allowed=[] (maximum surface)
// @rule:KAV-068 Loop count runaway detection

import { readFileSync } from "fs";
import { loadConfig } from "../../core/config";
import { getSessionSpawnCount, getBudgetState } from "../../core/db";
import { PERM, requiredBitsForTool } from "../../kavach/perm-mask";
import { checkValve } from "../../kavach/gate-valve";
import { loadAgent, transitionState } from "../../sandbox/quarantine";
import { loadPolicy } from "../../sandbox/policy-loader";
import { isStopRequested } from "../../core/db";

function readStdin(): string {
  try {
    return readFileSync("/dev/stdin", "utf-8");
  } catch {
    return "";
  }
}

export default async function checkSpawn(_args: string[]): Promise<void> {
  try {
    const stdin = readStdin().trim();
    const config = loadConfig();
    const enforce = config.enforcement?.mode === "enforce";
    const sessionId = process.env.CLAUDE_SESSION_ID || "unknown";

    // --- V2-048: L1 Soft Stop check before any spawn ---
    {
      const agentId = process.env.CLAUDE_AGENT_ID || sessionId;
      try {
        if (isStopRequested(agentId)) {
          process.stderr.write(`\n[KAVACH:stop] L1 SOFT STOP — ${agentId} has stop_requested. Spawn blocked.\n\n`);
          process.exit(2);
        }
      } catch {}
    }

    // --- Level 0: perm_mask SPAWN_AGENTS bit check (KAV-061) ---
    {
      const agentId = process.env.CLAUDE_AGENT_ID || sessionId;
      const valveResult = checkValve(agentId, PERM.SPAWN_AGENTS, 0);
      if (!valveResult.allowed) {
        process.stderr.write(
          `\n[KAVACH:L0] SPAWN_AGENTS blocked — ${valveResult.reason}\n` +
          `[KAVACH:L0] Valve state: ${valveResult.valve_state}\n\n`
        );
        process.exit(2);
      }
    }

    // --- HanumanG 7-axis check (KAV-015) ---
    if (stdin) {
      let toolInput: { tool_input?: { subagent_type?: string; prompt?: string; description?: string } } = {};
      try { toolInput = JSON.parse(stdin); } catch { /* ignore */ }

      const { checkHanumanG } = await import("../../shield/hanumang");
      const spawns = getSessionSpawnCount(sessionId);
      const daily = getBudgetState("daily", config.budget.daily_limit_usd);

      const hResult = checkHanumanG({
        agent_description: toolInput.tool_input?.description ?? toolInput.tool_input?.subagent_type,
        prompt: toolInput.tool_input?.prompt,
        parent_agent_id: sessionId,
        parent_budget_remaining_usd: daily.remaining_usd,
        child_budget_cap_usd: config.budget.daily_limit_usd,
        parent_depth: spawns,
        max_depth: config.budget.spawn_limit_per_session,
      });

      if (!hResult.passed && enforce) {
        process.stderr.write([
          ``,
          `╔══════════════════════════════════════════════════════════════╗`,
          `║  AEGIS HanumanG — AGENT SPAWN BLOCKED                        ║`,
          `╚══════════════════════════════════════════════════════════════╝`,
          ``,
          `  Failed axes : ${hResult.failed_axes.join(", ")}`,
          `  Reason      : ${hResult.reason}`,
          ``,
        ].join("\n"));
        process.exit(2);
      } else if (!hResult.passed) {
        process.stderr.write(`[HanumanG] WARN: spawn has delegation issues — ${hResult.failed_axes.join(", ")}\n`);
      }
    }

    // --- Phase 1b: MVT surface check (V2-036, V2-037) ---
    // @rule:KAV-067 — warn when spawning agent has maximum tool surface (tools_allowed=[])
    // @rule:INF-KAV-012 — low identity + max surface → force violation_threshold=1
    {
      const agentId = process.env.CLAUDE_AGENT_ID || sessionId;
      const policy = loadPolicy(agentId);
      if (policy && policy.tools_allowed.length === 0) {
        const allToolCount = 18; // Claude Code tool surface: ~18 registered tools
        process.stderr.write(
          `[KAVACH:MVT] WARN: agent ${agentId} has unrestricted tool surface (${allToolCount} tools) — declare tools_allowed in policy to minimize attack surface — KAV-067\n`
        );
        // INF-KAV-012: low identity confidence + max surface → strictest threshold
        if (policy && !["declared", "convention"].includes(policy.schema_version)) {
          // identity_confidence comes from AgentRecord (not policy)
          const agentRecord = loadAgent(agentId);
          if (agentRecord && !["declared", "convention"].includes(agentRecord.identity_confidence)) {
            // Emit to stderr as a tightening advisory — enforcement is done in enforcers.ts via violation_threshold
            process.stderr.write(
              `[KAVACH:MVT] TIGHTEN: identity_confidence=${agentRecord.identity_confidence} + max surface → violation_threshold forced to 1 — INF-KAV-012\n`
            );
          }
        }
      }
    }

    // --- Phase 1b: Loop count escalation (V2-038) ---
    // @rule:KAV-068 — if agent has made >30 tool calls without completing, warn; >50 → QUARANTINE
    {
      const agentId = process.env.CLAUDE_AGENT_ID || sessionId;
      const agentRecord = loadAgent(agentId);
      if (agentRecord) {
        const loopCount = agentRecord.loop_count ?? 0;
        if (loopCount > 50) {
          if (enforce) {
            const result = transitionState(agentId, "QUARANTINED", {
              reason: `loop_count=${loopCount} > 50 — runaway agent detected`,
              rule: "INF-KAV-014",
            });
            if (result.success) {
              process.stderr.write(
                `\n[KAVACH:loop] QUARANTINE: ${agentId} loop_count=${loopCount} — INF-KAV-014\n\n`
              );
              process.exit(2);
            }
          } else {
            process.stderr.write(
              `[KAVACH:loop] WARN: ${agentId} loop_count=${loopCount} > 50 — possible runaway agent — INF-KAV-014\n`
            );
          }
        } else if (loopCount > 30) {
          process.stderr.write(
            `[KAVACH:loop] WARN: ${agentId} loop_count=${loopCount} > 30 — monitoring for runaway behavior — KAV-YK-014\n`
          );
        }
      }
    }

    // --- Spawn count check ---
    const spawns = getSessionSpawnCount(sessionId);
    const limit = config.budget.spawn_limit_per_session;

    if (spawns >= limit) {
      const msg = `AEGIS: Agent spawn limit ${spawns}/${limit}`;
      if (enforce) {
        process.stderr.write(msg + " — BLOCKED. Run: aegis budget set spawn <N>\n");
        process.exit(2);
      } else {
        process.stderr.write(msg + " — WARNING (enforce mode off)\n");
      }
    } else if (spawns >= limit * 0.8) {
      process.stderr.write(`AEGIS: ${spawns}/${limit} agent spawns used this session\n`);
    }

    const daily = getBudgetState("daily", config.budget.daily_limit_usd);
    if (daily.remaining_usd < config.budget.cost_estimate_threshold_usd && enforce) {
      process.stderr.write(`AEGIS: Only $${daily.remaining_usd.toFixed(2)} remaining — spawn BLOCKED\n`);
      process.exit(2);
    }

    // --- V2-052: Tree depth enforcement (KAV-008, INF-KAV-004) ---
    // Count delegation chain length for this agent; block all further spawns if >= max_depth
    {
      const agentId = process.env.CLAUDE_AGENT_ID || sessionId;
      const agentRecord = loadAgent(agentId);
      const maxDepth = config.budget.max_depth ?? 5;
      if (agentRecord && agentRecord.depth >= maxDepth) {
        const msg = `[KAVACH:depth] Agent ${agentId} is at depth ${agentRecord.depth}/${maxDepth} — no further spawns permitted — INF-KAV-004`;
        if (enforce) {
          process.stderr.write(`\n${msg}\n\n`);
          process.exit(2);
        } else {
          process.stderr.write(`${msg} (warn only)\n`);
        }
      }
    }

    process.exit(0);
  } catch {
    process.exit(0); // never block on AEGIS internal errors
  }
}
