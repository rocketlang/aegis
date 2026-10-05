// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

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
// @rule:GNT-001 child.trust_mask = parent.trust_mask & requested — never union
// @rule:KAV-100 — the session comes from the hook's payload, and the input is read from
//                 fd 0 (hook-input.ts). Until 2.6.0 this hook read "/dev/stdin", which is
//                 unreadable when stdin is a socket, and took the session only from an
//                 environment variable: the delegation check was skipped by a harness, and
//                 every per-session check ran against "unknown".
//
// THIS HOOK FAILS OPEN on a fault of its own (it exits 0 and says so on stderr).
//
// The Level 0 valve check runs only when `kavach.perm_mask_levels` is "live" — the same
// switch, with the same quiet default, that check-destructive uses for Levels 0 and 1. It
// is a permission decision about a session, so it is switched on deliberately.

import { loadConfig, configFileProblem } from "../../core/config";
import { readHookInput } from "../hook-input";
import { getSessionSpawnCount, getBudgetState, recordBackgroundAgent } from "../../core/db";
import { loadEnvelopeBySessionId } from "../../core/ase";
import { computeChildMask, formatGnt001Log } from "../../kavach/genetic-trust";
import { PERM, requiredBitsForTool } from "../../kavach/perm-mask";
import { checkValve } from "../../kavach/gate-valve";
import { checkMudrika } from "../../kavach/mudrika-validator";
import { loadAgent, transitionState } from "../../sandbox/quarantine";
import { getAgentSwarm } from "../../sandbox/swarm";
import { loadPolicy } from "../../sandbox/policy-loader";
import { isStopRequested } from "../../core/db";
import { emitReceipt } from "../../kavach/pramana-emit";

export default async function checkSpawn(_args: string[]): Promise<void> {
  try {
    const input = readHookInput();
    const stdin = input.raw;
    const config = loadConfig();
    const enforce = config.enforcement?.mode === "enforce";
    const sessionId = input.sessionId;
    const callerId = input.agentId;
    const problem = configFileProblem();
    if (problem) process.stderr.write(`[AEGIS] ${problem} — running on the DEFAULT settings (mode: ${config.enforcement?.mode ?? "alert"})\n`);

    // --- Mudrika identity check (KOS-062) ---
    {
      const agentId = callerId;
      const mudrika = checkMudrika(agentId);
      if (!mudrika.valid && mudrika.reason !== "no mudrika — agent not registered") {
        process.stderr.write(`\n[KAVACH:MUDRIKA] IDENTITY DENIED — ${agentId}: ${mudrika.reason}\n\n`);
        process.exit(2);
      }
    }

    // --- V2-048: L1 Soft Stop check before any spawn ---
    {
      const agentId = callerId;
      try {
        if (isStopRequested(agentId)) {
          process.stderr.write(`\n[KAVACH:stop] L1 SOFT STOP — ${agentId} has stop_requested. Spawn blocked.\n\n`);
          process.exit(2);
        }
      } catch {}
    }

    // --- Level 0: perm_mask SPAWN_AGENTS bit check (KAV-061) — only when switched on ---
    if (((config.kavach ?? {}) as Record<string, unknown>).perm_mask_levels === "live") {
      const agentId = callerId;
      const valveResult = checkValve(agentId, PERM.SPAWN_AGENTS, 0);
      if (!valveResult.allowed) {
        process.stderr.write(
          `\n[KAVACH:L0] SPAWN_AGENTS blocked — ${valveResult.reason}\n` +
          `[KAVACH:L0] Valve state: ${valveResult.valve_state}\n\n`
        );
        process.exit(2);
      }
    }

    // --- Phase 1b: Loop count quarantine (V2-038, INF-KAV-014) ---
    // Checked before HanumanG: a runaway agent is quarantined regardless of spawn intent validity.
    // @rule:KAV-068 — >30 tool calls without completing → warn; >50 → QUARANTINE immediately
    {
      const agentId = callerId;
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

    // --- HanumanG 7-axis check (KAV-015) ---
    if (stdin) {
      // input that is not a JSON object is a spawn with nothing declared: the axes judge it
      const toolInput = (input.payload ?? {}) as { tool_input?: { subagent_type?: string; prompt?: string; description?: string } };

      const { checkHanumanG } = await import("../../shield/hanumang");
      const spawns = getSessionSpawnCount(sessionId);
      const daily = getBudgetState("daily", config.budget.daily_limit_usd);

      const hResult = checkHanumanG({
        agent_description: toolInput.tool_input?.description ?? toolInput.tool_input?.subagent_type,
        prompt: toolInput.tool_input?.prompt,
        parent_agent_id: sessionId,
        parent_budget_remaining_usd: daily.remaining_usd,
        child_budget_cap_usd: daily.remaining_usd,
        parent_depth: spawns,
        max_depth: config.budget.spawn_limit_per_session,
      });

      // @rule:KAV-046 — receipt every engaged HanumanG decision (a failed axis set).
      // Passing spawns are not receipted (would flood the chain with clean spawns).
      if (!hResult.passed) {
        emitReceipt(
          "HANUMANG",
          enforce ? "BLOCKED" : "ALLOWED",
          {
            session_id: sessionId,
            rule_id: "KAV-015",
            reason: hResult.reason,
            context: { failed_axes: hResult.failed_axes },
          },
          {
            rule_applied: "KAV-015",
            decision_path: `HANUMANG -> failed[${hResult.failed_axes.join("|")}] -> ${enforce ? "BLOCKED" : "ALERT_ONLY"}`,
            human_in_loop: false,
          },
        );
      }

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

      // @rule:KOS-T095 — record background spawns so Stop hook can warn before session kill
      const isBackground = (toolInput as { tool_input?: { run_in_background?: boolean } })?.tool_input?.run_in_background === true;
      if (isBackground) {
        try {
          recordBackgroundAgent(
            sessionId,
            (toolInput as { tool_input?: { description?: string } }).tool_input?.description,
            (toolInput as { tool_input?: { subagent_type?: string } }).tool_input?.subagent_type,
          );
          process.stderr.write(`[KAVACH:bg] background agent recorded — Stop hook will guard until acknowledged\n`);
        } catch {}
      }
    }

    // --- KAV-093: Cross-swarm spawn detection ---
    // If the spawning agent belongs to a swarm, warn that the new agent should be enrolled
    // in the same swarm (or DAN Gate approval is required for a different swarm).
    {
      const agentId = callerId;
      const spawnerSwarm = getAgentSwarm(agentId);
      if (spawnerSwarm) {
        process.stderr.write(
          `[KAVACH:swarm] spawner ${agentId} belongs to swarm ${spawnerSwarm.swarm_id} (mask=0x${spawnerSwarm.swarm_mask.toString(16)}) — ` +
          `enroll new agent via createSwarm/enrollAgent to apply KAV-090 ceiling (KAV-093)\n`
        );
      }
    }

    // --- Phase 1b: MVT surface check (V2-036, V2-037) ---
    // @rule:KAV-067 — warn when spawning agent has maximum tool surface (tools_allowed=[])
    // @rule:INF-KAV-012 — low identity + max surface → force violation_threshold=1
    {
      const agentId = callerId;
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
      const agentId = callerId;
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

    // --- BMOS-T-016: Expiry gate on spawner session ---
    // @rule:BMOS-008 Expiry gate: a spawner whose session has expired cannot issue new spawns
    {
      const agentId = callerId;
      try {
        const spawnerEnvelope = loadEnvelopeBySessionId(agentId);
        if (spawnerEnvelope?.expires_at && spawnerEnvelope.expires_at !== "task_end" && spawnerEnvelope.expires_at !== "") {
          const expired = new Date(spawnerEnvelope.expires_at).getTime() < Date.now();
          if (expired) {
            const msg = `[BMOS:expiry] Spawner ${agentId} session expired at ${spawnerEnvelope.expires_at} — spawn blocked (BMOS-008)`;
            if (enforce) {
              process.stderr.write(`\n${msg}\n\n`);
              process.exit(2);
            } else {
              process.stderr.write(`${msg} (warn only)\n`);
            }
          }
        }
      } catch { /* non-fatal */ }
    }

    // @rule:AGS-003 Issue SDT for the spawned agent at spawn-time (intra-org, local-signed)
    // @rule:GNT-001 child mask = parent trust_mask & requested — never hardcode a ceiling
    // This gives the child agent its delegation envelope before it starts executing.
    // Failure is non-fatal — the child can still run; it just won't carry an SDT.
    try {
      const agentId = callerId;
      const agentDepth = (loadAgent(agentId)?.depth ?? 0) + 1;
      const parentId = agentId !== sessionId ? agentId : undefined;

      // GNT-001: read parent trust_mask from the envelope store. Default to 1 (read-only) if unknown.
      const parentEnvelope = loadEnvelopeBySessionId(agentId);
      const parentTrustMask = parentEnvelope?.trust_mask ?? 1;

      // Child requests full inheritance — parent mask is the ceiling, bitmask AND enforces it.
      // A child cannot request more than the parent holds; computeChildMask ensures this.
      const gntResult = computeChildMask(parentTrustMask);
      process.stderr.write(formatGnt001Log(gntResult) + "\n");

      // @rule:BMOS-008 TTL inheritance: child SDT expiry <= parent session expiry (BMOS-T-017)
      // If parent has a concrete expiry, child cannot outlive it. "task_end" = no wall-clock bound.
      const parentExpiry = parentEnvelope?.expires_at && parentEnvelope.expires_at !== "" && parentEnvelope.expires_at !== "task_end"
        ? parentEnvelope.expires_at
        : "task_end";

      const { issueSdt } = await import("../../auth/sdt");
      const sdtResult = issueSdt({
        agent_id: `child-${Date.now()}`,
        agent_class: "worker",
        spawner_id: agentId,
        parent_token_id: parentId ? agentId : undefined,
        requested_mask: gntResult.child_mask,
        task_scope: [],           // unconstrained — policy layer may narrow later
        max_depth: config.budget.max_depth ?? 5,
        expiry: parentExpiry,
      });
      process.stderr.write(
        `[KAVACH:sdt] SDT issued: depth=${sdtResult.token.delegation.depth} ` +
        `mask=0x${sdtResult.effective_mask.toString(16)} id=${sdtResult.token.token_id.slice(0, 8)}\n`
      );
    } catch { /* non-fatal */ }

    process.exit(0);
  } catch (err) {
    // Fails OPEN (see the header). Say so: a check that broke silently looks like a pass.
    try { process.stderr.write(`[AEGIS] check-spawn could not run its checks — this call was NOT checked (${String((err as Error)?.message ?? err).slice(0, 120)})\n`); } catch {}
    process.exit(0);
  }
}
