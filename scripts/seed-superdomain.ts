#!/usr/bin/env bun
// Seed 38 KAVACH rules to SuperDomain
// POST http://localhost:4160/api/import/xshieldai-kavach
// Auto-type: INF-KAV-* → inference | KAV-YK-* → meta-reasoning | KAV-* → statute

const SUPERDOMAIN_URL = "http://localhost:4160";
const DOMAIN = "xshieldai-kavach";

const rules = [
  // ── SHASTRA (statute) ──────────────────────────────────────────────────────
  {
    id: "KAV-001",
    title: "Pre-Execution Intercept Supremacy",
    body: "The PreToolUse hook is the only layer where agent harm can be stopped, not just audited. All critical KAVACH enforcement rules MUST fire at PreToolUse. PostToolUse fires after tool execution — a DROP DATABASE or rm -rf has already completed. Pre-execution is the only viable prevention surface.",
    ruleType: "statute",
    domain: DOMAIN,
    status: "certified",
  },
  {
    id: "KAV-002",
    title: "All Agents Must Register Before First Tool Call",
    body: "Every agent operating within a KAVACH-governed session must register in the session-agent registry before its first tool call is allowed to proceed. An unregistered agent has no policy, no budget allocation, and no violation counter. Treated as identity_confidence: unknown and subject to most conservative default policy.",
    ruleType: "statute",
    domain: DOMAIN,
    status: "certified",
  },
  {
    id: "KAV-003",
    title: "Budget Inherits Downward, Never Escalates Upward",
    body: "A child agent's budget cap must always be less than or equal to its declared slice of the parent's budget. The sum of all child caps at any level must not exceed the parent's remaining cap at registration time. A child that overspends cannot draw from the parent pool beyond its declared allocation.",
    ruleType: "statute",
    domain: DOMAIN,
    status: "certified",
  },
  {
    id: "KAV-004",
    title: "Quarantine Is Freeze-Not-Kill — Human Holds the Release Key",
    body: "Quarantine state preserves the agent process in a frozen state with all tool calls blocked. It does NOT kill the agent. The quarantined agent can be force-closed (L1-L4) or released by an authorized operator after reviewing violations. No automatic release path exists — human in the loop is mandatory.",
    ruleType: "statute",
    domain: DOMAIN,
    status: "certified",
  },
  {
    id: "KAV-005",
    title: "DB Scope Is Enforced at the Hook Layer, Not Only at the PostgreSQL Role Layer",
    body: "An agent's db_scope policy is checked by KAVACH at PreToolUse before the Bash command reaches PostgreSQL. Relying on database-level roles alone is insufficient because psql commands can be embedded in scripts that bypass normal access patterns. The hook layer is the earlier and more reliable enforcement point.",
    ruleType: "statute",
    domain: DOMAIN,
    status: "certified",
  },
  {
    id: "KAV-006",
    title: "Path Deny Takes Precedence Over Path Allow",
    body: "When evaluating path_scope and path_deny in an agent policy, a path that matches any deny rule is blocked regardless of whether it also matches an allow rule. Deny-first precedence prevents misconfigured allow lists from inadvertently creating access to sensitive paths.",
    ruleType: "statute",
    domain: DOMAIN,
    status: "certified",
  },
  {
    id: "KAV-007",
    title: "Bash Allowlist Is Default-Deny When Configured",
    body: "If an agent policy declares a non-empty bash_allowlist, then any Bash first-token not on the allowlist is blocked. An empty allowlist means no Bash restriction (default open). This is different from a deny-list which supplements blocking on top of allow. The distinction must be explicit in every policy.",
    ruleType: "statute",
    domain: DOMAIN,
    status: "certified",
  },
  {
    id: "KAV-008",
    title: "Sub-Agent Tree Depth Is Bounded at max_depth",
    body: "The KAVACH session-agent registry tracks depth as an integer inherited from the parent at registration. Any agent spawn that would exceed the configured max_depth is blocked at the PreToolUse hook before the Agent tool call is executed. This prevents unbounded recursive agent spawning.",
    ruleType: "statute",
    domain: DOMAIN,
    status: "certified",
  },
  {
    id: "KAV-009",
    title: "Cost Rate Throttle Fires Before Cap Is Hit, Using Projected Cost",
    body: "KAVACH computes a projected session cost using EWMA (α=0.3) of per-call cost. At 80% of the declared cap, a warning is fired. At 95%, an L1 Soft Stop is triggered. The agent's current tool call is still allowed at the warning threshold; it is blocked at soft-stop. This prevents agents from depleting caps without warning.",
    ruleType: "statute",
    domain: DOMAIN,
    status: "certified",
  },
  {
    id: "KAV-010",
    title: "Resume Manifest Is Mandatory for All L1–L3 Force Closes",
    body: "When an agent is force-closed at L1, L2, or L3, KAVACH must write a resume manifest before marking the agent FORCE_CLOSED. The manifest contains: completed steps, in-progress step, pending steps, files_modified, dbs_touched, git_state, and a resume_prompt. The manifest enables a new agent to continue without re-doing completed work.",
    ruleType: "statute",
    domain: DOMAIN,
    status: "certified",
  },
  {
    id: "KAV-011",
    title: "Every Agent Must Have a Traceable Identity via Fallback Chain",
    body: "Agent identity is resolved via fallback: ANCHOR mudrika (highest confidence) → CLAUDE_AGENT_ID env → parent session ID → hash(PID+timestamp) (lowest confidence). The confidence level determines which enforcement mode applies. An untraceable agent is treated as unknown and subject to the most restrictive policy.",
    ruleType: "statute",
    domain: DOMAIN,
    status: "certified",
  },
  {
    id: "KAV-012",
    title: "Orphan Agents Are Automatically Elevated to ALERT State",
    body: "An orphan agent is one whose parent agent has reached a terminal state (FORCE_CLOSED, KILLED, COMPLETED) while the child remains RUNNING. The watchdog daemon detects this within 30 seconds and transitions the orphan to ORPHAN state. After a 5-minute TTL, a L1 Soft Stop is requested.",
    ruleType: "statute",
    domain: DOMAIN,
    status: "certified",
  },
  {
    id: "KAV-013",
    title: "Zombie Agents Are Auto-Force-Closed After max_zombie_timeout",
    body: "A zombie agent has a RUNNING state but no heartbeat (last_seen > heartbeat_timeout) and its PID is absent from the process table. The watchdog promotes it to ZOMBIE state. After max_zombie_timeout (2 minutes), it is force-closed and a resume manifest is written if the agent has completed any steps.",
    ruleType: "statute",
    domain: DOMAIN,
    status: "certified",
  },
  {
    id: "KAV-014",
    title: "Prompt Injection Fingerprints Are Checked on ALL Bash Tool Inputs",
    body: "The LakshmanRekha module runs 13 ordered injection-detection patterns against every Bash tool input regardless of agent identity confidence. QUARANTINE patterns fire immediately. BLOCK patterns exit 2 in enforce mode and emit warnings in alert mode. The scan is not skipped for trusted agents — all agents are PIV candidates.",
    ruleType: "statute",
    domain: DOMAIN,
    status: "certified",
  },
  {
    id: "KAV-015",
    title: "HanumanG's 7 Axes Are Checked at Every Agent Tool Spawn, Not Just the First",
    body: "The HanumanG delegation check (identity, budget, depth, parent_state, loop_count, tools_surface, velocity) runs on EVERY Agent tool call, not just the first spawn. An agent that was trusted at spawn can become untrusted during execution if its parent reaches a terminal state or its budget runs out.",
    ruleType: "statute",
    domain: DOMAIN,
    status: "certified",
  },
  {
    id: "KAV-016",
    title: "Soft Stop (L1) Is the Default Force-Close Level — Emergency Kill (L4) Requires Explicit Human Flag",
    body: "When KAVACH determines that an agent must be force-closed, the default level is L1 (Soft Stop: set stop_requested flag, block next tool call). L4 (Emergency Kill: SIGKILL) requires explicit human authorization via dashboard or Telegram approval. Automatic escalation past L1 is only allowed for runaway velocity anomalies.",
    ruleType: "statute",
    domain: DOMAIN,
    status: "certified",
  },
  {
    id: "KAV-017",
    title: "AI Proxy Intercept Captures Per-Agent Token Usage from API Response Body",
    body: "The ANKR AI Proxy intercepts every /v1/chat response, reads the X-KAVACH-Agent-ID request header, and POSTs token usage + cost_usd to the AEGIS /api/v1/agent-usage ingest endpoint. This is non-blocking (2s timeout, fire-and-forget). AEGIS is a recipient, not a dependency of the proxy.",
    ruleType: "statute",
    domain: DOMAIN,
    status: "certified",
  },
  {
    id: "KAV-018",
    title: "Budget Inheritance: Child Allocation ≤ Declared Slice of Parent; Sum of Children ≤ Parent Cap",
    body: "At registration, the child declares a budget_cap_usd. KAVACH checks: (a) child cap <= parent remaining budget, (b) sum of all active child caps <= parent cap - parent_used. If either check fails, registration is rejected. On child COMPLETED, unused cap (child_cap - child_used) is returned to the parent's budget pool.",
    ruleType: "statute",
    domain: DOMAIN,
    status: "certified",
  },
  {
    id: "KAV-019",
    title: "Watchdog Daemon Runs as Persistent systemd Service, Not Just on Tool Calls",
    body: "The KAVACH watchdog (aegis-watchdog.service) is a persistent daemon independent of tool call cadence. It polls aegis.db every 30 seconds to detect time-based threats: zombie agents, orphan agents, cost velocity spikes. This provides protection even when an agent is idle and no hook fires.",
    ruleType: "statute",
    domain: DOMAIN,
    status: "certified",
  },
  {
    id: "KAV-020",
    title: "Open-Source Core Ships Generic Rules; xShieldAI Wraps with Domain Signatures",
    body: "The OSS @rocketlang/aegis package ships only generic injection patterns (INJ-001..012) with no ANKR or maritime domain signatures. The xShieldAI commercial layer wraps KAVACH with domain-specific injection signatures, compliance report templates, and enterprise dashboard. The OSS/commercial split is at the rule file boundary.",
    ruleType: "statute",
    domain: DOMAIN,
    status: "certified",
  },
  // ── YUKTI (meta-reasoning) ─────────────────────────────────────────────────
  {
    id: "KAV-YK-001",
    title: "Why Pre-Execution Intercept Beats Post-Audit",
    body: "The autopsy vs ER argument: a PostToolUse audit is an autopsy — it establishes what happened after the patient is dead. A PreToolUse intercept is emergency medicine — it can prevent the harm. For governance of AI agents, only prevention rules count. Any rule that fires after execution is evidence collection, not harm prevention. Design governance rules for pre-execution.",
    ruleType: "meta-reasoning",
    domain: DOMAIN,
    status: "certified",
  },
  {
    id: "KAV-YK-002",
    title: "How to Classify a Force-Close Level",
    body: "L1 Soft Stop: set stop_requested=true, block on next tool call — reversible, agent can resume. L2 Ordered Shutdown: write manifest + transition to FORCE_CLOSED — reversible via resume. L3 SIGSTOP: pause process, preserve state — operator must SIGCONT. L4 Emergency Kill: SIGKILL + FORCE_CLOSED — irreversible, no resume. Escalate only when lower level is insufficient.",
    ruleType: "meta-reasoning",
    domain: DOMAIN,
    status: "certified",
  },
  {
    id: "KAV-YK-003",
    title: "How to Construct the Budget Inheritance Tree When a New Sub-Agent Is Spawned",
    body: "At spawn: (1) resolve parent agent from registry using parent_session_id, (2) check parent remaining = parent_cap - parent_used - sum(active_children_caps), (3) if child_cap > parent_remaining → reject spawn, (4) reserve child_cap from parent's budget_pool_reserved, (5) link child depth = parent.depth + 1. On child close: return child_cap - child_used to parent pool.",
    ruleType: "meta-reasoning",
    domain: DOMAIN,
    status: "certified",
  },
  {
    id: "KAV-YK-004",
    title: "How to Distinguish a Rogue Agent from a Misconfigured One",
    body: "Rogue indicators: velocity spike + injection fingerprint match + unknown identity confidence + attempts to read /root/.ssh or credential files. Misconfigured indicators: policy violation without injection signal + known identity + low violation count + no exfil pattern. Rogue → QUARANTINE immediately. Misconfigured → BLOCK + notify operator. Do not quarantine misconfigured agents — operator needs to fix policy.",
    ruleType: "meta-reasoning",
    domain: DOMAIN,
    status: "certified",
  },
  {
    id: "KAV-YK-005",
    title: "When to Quarantine vs When to Block a Single Call",
    body: "Block a single call when: single low-severity violation, known agent identity, no previous violations. Quarantine when: CRITICAL violation (credential read, persistence write, injection fingerprint), OR 3+ MEDIUM violations in same session, OR unknown identity + HIGH signal, OR velocity anomaly > 120 calls/min. Quarantine is session-level freeze; block is single-call denial.",
    ruleType: "meta-reasoning",
    domain: DOMAIN,
    status: "certified",
  },
  {
    id: "KAV-YK-006",
    title: "How to Write a Resume Manifest That a New Agent Can Reliably Continue From",
    body: "A resume manifest must contain: (1) completed_steps with tool names + outcomes, (2) in_progress_step with exact state at interruption, (3) pending_steps list, (4) files_modified with paths, (5) dbs_touched with table names, (6) git_state (branch + dirty files), (7) resume_prompt as a paste-ready instruction for a new agent session. The manifest must be written before FORCE_CLOSED transition.",
    ruleType: "meta-reasoning",
    domain: DOMAIN,
    status: "certified",
  },
  {
    id: "KAV-YK-007",
    title: "How to Handle Conflicting Policies — Parent More Restrictive Than Child",
    body: "Parent-wins intersection rule: the effective policy for a child agent is the intersection (most restrictive) of its own policy and its parent's policy. If parent denies /etc and child allows /etc, the effective scope denies /etc. If parent allows only [Read, Write] and child declares [Read, Write, Bash], the effective tools are [Read, Write]. Never escalate permissions through parent/child boundaries.",
    ruleType: "meta-reasoning",
    domain: DOMAIN,
    status: "certified",
  },
  {
    id: "KAV-YK-008",
    title: "How to Assess Identity Confidence Level and Apply Enforcement Mode",
    body: "HIGH confidence (mudrika present, ANCHOR-verified): full policy enforcement, all 3 gates active. MEDIUM confidence (CLAUDE_AGENT_ID env only): enforce mode regardless of config setting. LOW confidence (parent session fallback): enforce mode + tighter violation_threshold (halved). UNKNOWN (hash-only): enforce mode + violation_threshold=1 (any violation → quarantine).",
    ruleType: "meta-reasoning",
    domain: DOMAIN,
    status: "certified",
  },
  {
    id: "KAV-YK-009",
    title: "The Agent Transaction Model — Why Agent Work Must Be Treated as Distributed Transactions",
    body: "Agent work is a distributed transaction: start (register), operations (tool calls), commit (close) or abort (force-close). Like a DB transaction, partial completion must be detectable and recoverable. The resume manifest is the transaction log. Quarantine is the equivalent of a transaction rollback marker. Without register/close boundaries, agent work cannot be governed, billed, or recovered.",
    ruleType: "meta-reasoning",
    domain: DOMAIN,
    status: "certified",
  },
  {
    id: "KAV-YK-010",
    title: "How to Determine When Projected Cost Pre-Stop Should Fire vs When to Wait",
    body: "Fire projected-cost pre-stop when: EWMA burn rate × remaining_time_to_cap < buffer_window (default 5 minutes of runway). Do NOT fire: when the agent is in a burst phase declared at registration, or when the projected cost is within 5% of the last projection (avoid thrashing). The 80%/95% thresholds are session-level; per-call EWMA is the fine-grained signal.",
    ruleType: "meta-reasoning",
    domain: DOMAIN,
    status: "certified",
  },
  // ── VIVEKA (inference) ─────────────────────────────────────────────────────
  {
    id: "INF-KAV-001",
    title: "SSH Key Read → Immediate QUARANTINE",
    body: "IF agent reads any file matching /root/.ssh/*, /home/*/.ssh/*, id_rsa, id_ed25519, known_hosts via Read tool OR cat/cp/base64 via Bash THEN verdict=QUARANTINE, rule=INF-KAV-001. No intermediate BLOCK step. SSH key exfil is a terminal event — freeze immediately and require human release.",
    ruleType: "inference",
    domain: DOMAIN,
    status: "certified",
  },
  {
    id: "INF-KAV-002",
    title: "Agent Velocity > 60 Tool Calls/Minute → Throttle",
    body: "IF agent tool_call_rate (60-second rolling window) > 60/min THEN request_stop=true + emit VELOCITY_SPIKE SENSE event + alert. IF rate > 120/min THEN transition to QUARANTINE + emit kavach.agent.quarantined. Velocity anomaly is a runaway indicator even without an injection signature. The watchdog daemon evaluates this every 30 seconds.",
    ruleType: "inference",
    domain: DOMAIN,
    status: "certified",
  },
  {
    id: "INF-KAV-003",
    title: "Unknown Identity + HIGH Signal → Direct QUARANTINE",
    body: "IF identity_confidence=UNKNOWN AND (injection_fingerprint_match OR credential_read OR persistence_write) THEN verdict=QUARANTINE immediately. Do not apply WARN or BLOCK escalation steps for unknown identity + high-severity signal. Unknown identity means the agent cannot prove it was authorised to be here; a high signal means it is actively doing something dangerous.",
    ruleType: "inference",
    domain: DOMAIN,
    status: "certified",
  },
  {
    id: "INF-KAV-004",
    title: "Sub-Agent Tree Depth Reaches max_depth → Block ALL Further Agent Tool Calls",
    body: "IF agent.depth >= config.budget.max_depth THEN block ALL Agent tool calls for this agent (not just the current one). The block is NOT a soft stop — it is a policy violation. Record violation + emit WARN. The agent can continue other tool types (Read, Write, Bash within policy) but cannot spawn children. This prevents depth-based explosion attacks.",
    ruleType: "inference",
    domain: DOMAIN,
    status: "certified",
  },
  {
    id: "INF-KAV-005",
    title: "curl/wget After Large Read → Flag as Potential Exfil",
    body: "IF last_tool=Read AND read_size > 100KB AND current_tool=Bash AND bash_command matches (curl|wget|nc|ncat) THEN verdict=QUARANTINE, reason=potential_exfil_sequence. The sequence large-read→network-send is the canonical data exfiltration pattern. Either call alone is insufficient for QUARANTINE; the sequence is the signal.",
    ruleType: "inference",
    domain: DOMAIN,
    status: "certified",
  },
  {
    id: "INF-KAV-006",
    title: "Agent Writes to Persistence Targets → Immediate QUARANTINE",
    body: "IF Write or Edit tool targets persistence paths (/etc/cron*, ~/.bashrc, ~/.profile, ~/.zshrc, /etc/rc.local, systemd unit files, /usr/local/bin/*) OR Bash writes to these paths via echo/tee/cat redirect THEN verdict=QUARANTINE, rule=INF-KAV-006. Persistence is how an attacker survives a session kill. Freeze first, investigate second.",
    ruleType: "inference",
    domain: DOMAIN,
    status: "certified",
  },
  {
    id: "INF-KAV-007",
    title: "Parent Agent FORCE_CLOSED + Child Agents Still RUNNING → Mark Children ORPHAN",
    body: "IF parent_agent.state IN (FORCE_CLOSED, KILLED, ZOMBIE) AND child_agent.state=RUNNING THEN mark child as ORPHAN within 30 seconds (next watchdog poll). Record orphan_since timestamp. After orphan_TTL (5 minutes): emit SENSE ORPHAN_DETECTED + requestStop. The child may not know its parent was killed; the watchdog closes the gap.",
    ruleType: "inference",
    domain: DOMAIN,
    status: "certified",
  },
  {
    id: "INF-KAV-008",
    title: "Projected Session Cost at 80% of Cap → Alert; at 95% → Soft-Stop",
    body: "IF projected_cost (EWMA × remaining_turns) >= 0.80 × budget_cap THEN emit kavach.budget.threshold_warning + alert. IF projected_cost >= 0.95 × budget_cap THEN requestStop(agent_id) + emit kavach.budget.projected_stop. In enforce mode: exit 2 at 95% (blocks next tool call). In alert mode: warn only. The 80% and 95% thresholds are not configurable at per-agent level — they are universal policy.",
    ruleType: "inference",
    domain: DOMAIN,
    status: "certified",
  },
];

async function seed() {
  const url = `${SUPERDOMAIN_URL}/api/import/${DOMAIN}`;
  console.log(`Seeding ${rules.length} rules to SuperDomain: ${url}`);

  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ rules }),
  });

  const body = await res.json() as any;

  if (!res.ok) {
    console.error("SuperDomain import failed:", body);
    process.exit(1);
  }

  console.log(`✅ Seeded ${rules.length} rules`);
  console.log(`   imported: ${body.imported ?? "??"}`);
  console.log(`   skipped:  ${body.skipped ?? "??"}`);
  console.log(`   errors:   ${body.errors?.length ?? 0}`);
  if (body.errors?.length) {
    for (const e of body.errors) console.error("  ⚠", e);
  }
}

seed();
