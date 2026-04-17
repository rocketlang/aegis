# The Incident That Spawned AEGIS

**Date:** April 15-16, 2026
**User:** Capt. Anil Sharma, Founder, ANKR Labs
**Loss:** ~$200 in Max Plan credits, weekly usage fully exhausted
**Visibility:** None. CLI `/usage` explicitly says "Usage does not include other devices or claude.ai."

---

## What Happened

1. Closed Claude Code session.
2. Walked away.
3. Came back.
4. $200 gone. Weekly usage at 100%.
5. Local logs showed minimal activity.

The Claude Code CLI usage display doesn't include:
- claude.ai web usage
- Claude Code on other devices (Termux mobile, another machine)
- API key usage from any service (proxy, scripts, integrations)

So when usage is split across WSL + Termux + WebUI + any API-key-based service, **nobody sees the total until it's gone.**

---

## Root Cause Analysis

### Primary cause: No unified usage visibility across surfaces

User operates from 3+ surfaces (WSL, Termux, WebUI). Each shows only its own consumption. No single pane of glass exists.

### Contributing cause: Subagent multiplication

Claude Code's `Agent` tool spawns subagent sessions. On April 15, **120 subagent sessions spawned in one hour** from a single user instruction. Each spawn carries full context cost.

### Contributing cause: Large context per turn

Project `CLAUDE.md` was ~600 lines. Sent every turn. Combined with conversation history, each turn read 551,494 cached tokens. 752 messages × high context = enormous spend.

### Contributing cause: API keys in .env files

Three Anthropic API keys were embedded in `.env` files across the system, accessible to any service hitting the local AI proxy. Any service could consume credits silently.

### Contributing cause: No hard spending cap

Max Plan depletes silently rather than hard-stopping. No "stop at $X" control exists.

---

## The Five Missing Controls

Every agentic system in production needs these. None exist in Claude Code (or any comparable system) as of April 2026:

1. **Hard budget cap per agent, per session, per day** — not soft depletion
2. **Human heartbeat** — pause when user leaves, resume when returns
3. **Unified cross-surface usage view** — one dashboard, all sources
4. **Agent spawn cost estimation** — "this will spawn 207 agents, cost ~$150. Proceed?"
5. **Anomaly detection** — alert on spend spikes, night-time activity

AEGIS implements 1, 3, 4, 5 today. 2 (heartbeat) is Phase 1.

---

## The Paradigm Shift

| | Traditional SaaS | Agent-as-a-Service |
|---|---|---|
| Execution trigger | User clicks | User instructs, agent decides scope |
| Execution boundary | User stops, system stops | User stops, agents may continue |
| Cost model | Predictable per-seat/month | Variable per-token × agent count |
| Visibility | Dashboard shows all | Each surface shows only its own |
| Multiplication | 1 action = 1 action | 1 instruction = N spawns |
| Human presence | Implicitly required | Not required after initiation |

**Core risk statement:** If an agent can execute without you, it can also spend without you.

---

## Why This Incident Is Public

This is published as a signal, not a complaint. The paradigm shift from SaaS → AaaS is real and accelerating. The infrastructure to govern it does not exist yet. AEGIS is one attempt. More work is needed from Anthropic, OpenAI, and the broader ecosystem.

Key recommendations to vendors:

**Anthropic:**
- Add total account usage endpoint (across devices, surfaces, API keys)
- Expose `--max-budget-usd` to interactive Claude Code sessions
- Warn before large Agent tool spawns
- Implement human heartbeat for agentic sessions

**Industry:**
- Adopt a universal Agent Budget Attestation (ABA) protocol so agents carry budget state across vendor boundaries
- Billing models must evolve — per-seat assumes one human = one session; agentic breaks that

---

## Credits

This incident and response were documented in real-time as part of the ANKR Labs "irRegularAI" journal. The full root cause investigation is at [`/root/proposals/ankr--agentic-spend-incident--formal--2026-04-17.md`](https://github.com/rocketlang/aegis) in the source repo.
