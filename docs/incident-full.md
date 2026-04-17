# The First Real Risk of Agentic Systems in Production

**Incident Report + Root Cause Analysis + Architectural Thesis**

**Author:** Capt. Anil Sharma, Founder — ANKR Labs
**Date:** 2026-04-17
**Classification:** Public — intended for Anthropic visibility and industry discussion
**DOI:** (pending Zenodo publication)

---

## 1. What Happened

On April 15-16, 2026, approximately $200 in Claude Code (Anthropic Max Plan) credits were consumed without the user's active participation.

**Timeline of events:**

| Time | Event |
|------|-------|
| Apr 15, ~11:44 IST | User closes last interactive Claude Code session (53 messages) |
| Apr 15, 11:44 — 17:07 | **34 additional subagent sessions appear** in `/root/.claude/projects/` that user did not initiate |
| Apr 15, 03:47 | Woodpecker cron attempts run, OOM crash: `Fatal process OOM in Failed to reserve virtual memory for CodeRange` |
| Apr 16, 03:47 | Woodpecker skipped entirely (system load avg: 21) |
| Apr 16 | User returns. Weekly usage fully exhausted. ~$200 gap between local usage display and actual consumption |
| Apr 17 | Investigation begins |

**What the user observed:**
- Claude Code CLI's `/usage` shows local consumption only
- The dialog states: *"Usage does not include other devices or claude.ai"*
- Credits were gone. Weekly Max Plan allowance was fully exhausted
- Sessions existed that the user did not run

---

## 2. The Investigation — What We Found

### 2.1 Environment

The user operates Claude Code from **three surfaces**, all tied to the same Anthropic Max Plan account:

| Surface | Description |
|---------|-------------|
| **WSL (primary)** | Ubuntu on Windows, SSH to production VM (e2e-102-29) |
| **Termux (mobile)** | Claude Code on Android, SSH to same VM while commuting |
| **WebUI** | claude.ai web interface for conversations |

All three consume from the same weekly usage allowance. None shows the other's consumption.

### 2.2 Local Forensic Evidence (VM: e2e-102-29)

**Session inventory — Apr 15:**
- 3 interactive sessions in `/root/.claude/projects/-root/` (53 + 3 + 1 messages)
- **207 subagent sessions** in `/root/.claude/projects/-root-ankr-labs-nx-apps-ai-proxy/`
- Subagent burst: **120 sessions in one hour** (10:00-10:59 IST)

**Subagent composition (from meta.json analysis):**
- 1,311 "Explore" agents — scanning packages, services, microservice architecture
- 102 "Technical Writer" agents — summarizing findings
- 42 "general-purpose" agents — supporting tasks

**These were spawned by the Claude Code Agent tool during interactive sessions.** Each subagent is a separate API call with full context loading. The user initiated one task; the system spawned 207 sessions to fulfil it.

**Automated processes (cleared of responsibility):**
- **Woodpecker cron** (daily 3:47am): Budget-capped at $0.50/day via `--max-budget-usd 0.50`. OOM'd on Apr 15. Skipped Apr 16-17 (high load). NOT the cause.
- **No Claude Code CronCreate triggers** scheduled
- **No `/loop` or `ScheduleWakeup` patterns** found in any session log
- **No other scripts on the VM invoke `claude`**

### 2.3 API Key Exposure

**Three Anthropic API keys were found on the system:**

| Key | Location | Risk |
|-----|----------|------|
| `sk-ant-api03-liCr...` | `/root/.ankr/config/credentials.env` | Used by ai-proxy service |
| `sk-ant-api03-efl6...` | `/root/ankr-labs-nx/.env` | Used by NX monorepo services |
| `sk-ant-api03-liCr...` | `/root/ankr-labs-nx/apps/ai-proxy/.env` | Duplicate of key 1 |

The `ai-proxy` service (port 4444) routes all LLM calls for 200+ ANKR services. Any service hitting `http://localhost:4444` with an Anthropic-routed request would consume credits via these keys — **independently of Claude Code sessions.**

**Remediation:** All three keys were removed on 2026-04-17. Comment: `# REMOVED 2026-04-17 — uncontrolled spend incident. Rotate key before re-adding.`

### 2.4 Token Cost Estimation (Local Sessions Only, Apr 10-17)

From sampling the largest session files and extracting `usage` objects:

| Session | Date | Messages | Cache Read | Output | Est. Cost |
|---------|------|----------|-----------|--------|-----------|
| `2c00418c` | Apr 14 | 752 | 410M tokens | 3.1M | ~$1,100 |
| `a242a1ad` | Apr 14 | 184 | 41M tokens | 0.7M | ~$145 |
| `12575fd1` | Apr 15 | 53 | 8.4M tokens | 0.2M | ~$63 |
| 207 subagents | Apr 15 | ~207 | ~50M tokens | ~1M | ~$150 |
| Other sessions | Apr 10-17 | ~150 | ~200M tokens | ~2M | ~$600 |

**Estimated total local API cost (raw pricing): ~$2,000-6,000 for the week.**

Note: Max Plan pricing differs from raw API pricing. The exact conversion is opaque. But the pattern is clear: the 752-message session alone, reading 551K cached tokens per turn, consumed more in one sitting than the user expected to spend in a month.

### 2.5 Multi-Device Access Pattern

SSH auth.log analysis:
```
103.70.147.205-206  (Mobile/Residential) — Apr 12-15, concurrent pts/0-3
103.55.6.254        (Different ISP)      — Apr 15-17, current session
```

The user routinely has 2-4 concurrent SSH sessions from different IPs. Each can run an independent Claude Code instance. Usage from Termux sessions does not appear in the WSL session's `/usage` display.

---

## 3. Root Cause Analysis

### Primary cause: No unified usage visibility across surfaces

The user operates from 3 surfaces (WSL, Termux, WebUI). Each shows only its own consumption. There is no single pane of glass showing total account usage across all surfaces. The user's mental model was: "I stopped, so spending stopped." Reality: other surfaces (and their spawned agents) continued.

### Contributing cause: Subagent multiplication without cost visibility

When Claude Code uses the Agent tool, it spawns subagent sessions. One user instruction ("explore this codebase") became 207 separate API calls. The cost of subagent spawning is invisible to the user during execution. There is no prompt like "this will spawn ~200 agents, estimated cost: $X — proceed?"

### Contributing cause: Large context per turn

The ANKR project's `CLAUDE.md` is ~600 lines. This is sent with every API turn. Combined with conversation history, each turn in the 752-message session was reading 551,494 cached tokens. At Opus pricing, even cached reads accumulate rapidly across hundreds of turns.

### Contributing cause: API keys in environment files

Two distinct Anthropic API keys were embedded in `.env` files accessible to the `ai-proxy` service. Any programmatic call through the proxy could have consumed credits without generating a Claude Code session log.

### Contributing cause: No hard spending cap

The Max Plan has a weekly usage allowance, but it's a soft limit — it depletes silently rather than hard-stopping at a user-defined threshold. There is no "stop all execution if I've spent $X" control.

---

## 4. The Bigger Problem — From SaaS to Agent-as-a-Service

This incident is not about one tool or one bill. It is an early signal of a structural shift.

### 4.1 The Paradigm Change

| Dimension | Traditional SaaS | Agent-as-a-Service (AaaS) |
|-----------|-----------------|---------------------------|
| **Execution trigger** | User clicks | User instructs, agent decides scope |
| **Execution boundary** | User stops, system stops | User stops, agents may continue |
| **Cost model** | Predictable per-seat/month | Variable per-token, multiplied by agent count |
| **Visibility** | Dashboard shows all usage | Each surface shows only its own |
| **Multiplication** | 1 action = 1 action | 1 instruction = N agent spawns |
| **Human presence** | Implicitly required (UI) | Not required after initiation |

### 4.2 The Core Risk Statement

**If an agent can execute without you, it can also spend without you.**

This is not a bug. It is the natural consequence of autonomous execution without control boundaries.

In traditional computing:
```
You stop --> System stops
```

In agentic computing:
```
You stop --> System might continue
              --> Agents might spawn more agents
              --> Cost accumulates without human awareness
              --> No mechanism detects "the human left"
```

### 4.3 The Five Missing Controls

Every agentic system in production needs these. None currently exist in Claude Code (or any comparable system as of April 2026):

**1. Hard Budget Cap Per Agent (not per session, not per plan — per agent)**
```
agent.max_spend = $5.00
agent.on_limit = "stop_and_notify"  # not "silently deplete"
```

**2. Human Heartbeat Requirement**
```
# If no user interaction for N minutes, pause all agents
agent.heartbeat_timeout = 300  # seconds
agent.on_timeout = "pause"     # not "continue silently"
```

**3. Unified Cross-Surface Usage View**
```
GET /api/usage/total
{
  "surfaces": {
    "cli_wsl": { "cost": 42.30, "sessions": 3 },
    "cli_termux": { "cost": 18.50, "sessions": 1 },
    "web_ui": { "cost": 31.20, "sessions": 5 },
    "api_key_direct": { "cost": 108.00, "calls": 2340 }
  },
  "total": 200.00,
  "budget_remaining": 0.00
}
```

**4. Agent Spawn Cost Estimation**
```
# Before spawning 207 subagents:
"This task will spawn ~200 agents. Estimated cost: $150.
 Budget remaining: $180. Proceed? [y/N]"
```

**5. Anomaly Detection on Usage Spikes**
```
# Alert when spending rate exceeds 3x the rolling 7-day average
if (spend_rate > 3 * avg_7d):
    notify_user("Unusual spend detected")
    pause_non_critical_agents()
```

---

## 5. What ANKR Already Had (And What It Teaches)

ANKR's own woodpecker daemon — a Claude Code cron that runs daily — already implements 6 layers of guard:

```bash
# Guard 0: Suspension file (human review gate)
# Guard 1: RAM check (400MB floor)
# Guard 2: System load check (>8 = skip)
# Guard 3: Pre/post file count integrity check
# Guard 4: Deduplication (already ran today? skip)
# Guard 5: Budget cap ($0.50/day via --max-budget-usd)
# Guard 6: ulimit memory ceiling (512MB virtual)
```

This is 6 layers of defense for a $0.50/day cron job.

The interactive sessions — which cost 100-1000x more — have **zero layers of defense.**

The woodpecker's architecture is the right model. The gap is that it only governs one process on one machine. The broader account has no equivalent.

---

## 6. Remediation Actions Taken

| Action | Status | Date |
|--------|--------|------|
| Removed Anthropic API key from `/root/.ankr/config/credentials.env` | Done | 2026-04-17 |
| Removed Anthropic API key from `/root/ankr-labs-nx/.env` | Done | 2026-04-17 |
| Removed Anthropic API key from `/root/ankr-labs-nx/apps/ai-proxy/.env` | Done | 2026-04-17 |
| Documented incident in ANKR proposals | Done | 2026-04-17 |
| Rotate keys on Anthropic dashboard | **TODO** | - |
| Add budget cap to Claude Code interactive sessions | **Requested from Anthropic** | - |
| Add unified usage API across surfaces | **Requested from Anthropic** | - |

---

## 7. Recommendations to Anthropic

This is written in good faith by a power user who builds on Claude Code daily (225+ services, 2000+ proposals, 84 Zenodo papers — all built with Claude Code).

### 7.1 Immediate (next release)

1. **Show total account usage in `/usage`** — not just "this device." The current message *"Usage does not include other devices or claude.ai"* is a warning, not a solution.

2. **Add `--max-budget-usd` to interactive sessions** — the flag already exists for headless mode. Expose it for interactive use.

3. **Warn before large Agent tool spawns** — if the system is about to spawn >10 subagents, show estimated cost and ask for confirmation.

### 7.2 Medium-term (next quarter)

4. **Human heartbeat for agentic sessions** — if no user input for N minutes, pause execution and notify. The user should opt-in to "unattended mode" explicitly, not fall into it by default.

5. **Per-session cost tracking** — every session should display its cumulative token cost in the status bar, updating in real-time.

6. **Anomaly detection** — alert when daily spend exceeds 3x the 7-day rolling average.

### 7.3 Architectural (next year)

7. **Agent identity and cost attestation** — every agent spawn should carry a signed attestation: who initiated it, what budget it operates under, what it's authorized to do. This is the Nallasetu problem (agent trust protocol) applied to cost control.

8. **The AaaS billing model** — the industry needs a new billing paradigm that accounts for agent multiplication. Per-seat pricing assumed one human = one session. Agentic systems break that assumption. The billing model must evolve with the execution model.

---

## 8. The Thesis — Why This Matters Beyond One Incident

> "Autonomy without control = financial risk."

This was $200. It could have been $2,000 or $20,000. The structural problem scales linearly with agent capability:

- **Today:** 207 subagents spawned from one instruction
- **Tomorrow:** 2,000 subagents across 10 services
- **Next year:** autonomous agent networks executing 24/7 on your behalf, with your credit card

The controls we build now — budget caps, heartbeat checks, cost attestation, anomaly detection — are the seatbelts for the agentic era. We don't need them because we crashed. We need them because the road ahead is faster than the road behind.

---

## 9. Connection to ANKR Architecture

This incident validates three ANKR systems that were designed for exactly this class of problem:

| ANKR System | The Relevance |
|-------------|---------------|
| **Nallasetu** (Agent Trust Protocol) | Cross-org agent handshake. TLS-for-agent-commerce. If agents can spend, they need identity and authorization — not just API keys |
| **xShieldAI / LakshmanRekha** | LLM endpoint posture assessment. The AI Proxy (port 4444) had embedded API keys with no spend monitoring — this is exactly the posture gap LakshmanRekha was designed to detect |
| **Forja TRUST** | The trust bitmask: `(mask & CAN_SPEND) !== 0`. Every agent should declare its spending authority in a machine-readable, verifiable format. Not inferred. Binary. |
| **VIVECHANA** | `V = K x F`. The cost of this incident (V) was high because K (knowledge of the risk) was low and F (frequency of occurrence) was 1.0. Now K is high. F drops. V drops. The framework works. |

---

## 10. Closing Statement

This is not a rant. This is not a support ticket. This is a signal.

We are entering a world where the line between "tool" and "agent" is blurring. Tools wait for you. Agents act on your behalf. The billing, visibility, and control infrastructure has not caught up with this shift.

The first generation of agentic system users — the ones building with these tools today — are discovering these gaps with real money. The controls we demand now will become the defaults that protect everyone later.

Build the seatbelts before the highway, not after the accident.

---

**Filed as:** `ankr--agentic-spend-incident--formal--2026-04-17.md`
**Location:** `/root/proposals/`
**GRANTHX indexed:** auto (5-minute cycle)
**Viewer published:** pending `bash /root/ankr-publish-docs.sh 48h`

---

*Capt. Anil Sharma*
*Founder, ANKR Labs*
*capt.anil.sharma@powerpbox.org*
