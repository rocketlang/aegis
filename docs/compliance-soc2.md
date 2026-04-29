# AEGIS — SOC 2 AI System Compliance Reference

> This document maps AEGIS controls to SOC 2 Trust Service Criteria relevant to AI agent governance. Use as a reference when preparing for SOC 2 audits in organizations that deploy AI agents.

---

## Applicability

SOC 2 applies to service organizations that store, process, or transmit customer data. If your AI agents (Claude Code, OpenAI Codex, Cursor, etc.) access production systems, customer databases, or infrastructure, the following Trust Service Criteria (TSC) are relevant.

AEGIS provides evidence-generating controls for several SOC 2 criteria.

---

## Control Mapping

### CC6 — Logical and Physical Access Controls

| SOC 2 Criterion | AEGIS Control | Evidence |
|---|---|---|
| CC6.1 — Logical access is restricted to authorized users | **Agent Sandbox** — perm_mask restricts tool access per agent policy | `~/.aegis/agents/{id}.policy.json` |
| CC6.2 — Access is removed when no longer needed | **Agent lifecycle state machine** — agents transition to FORCE_CLOSED/KILLED | `aegis quarantine list` output |
| CC6.3 — Access to sensitive resources is restricted | **class_mask** — per-agent resource class restrictions (DB, network, filesystem) | `aegis valve status <id>` |

### CC7 — System Operations

| SOC 2 Criterion | AEGIS Control | Evidence |
|---|---|---|
| CC7.1 — Vulnerabilities are identified and monitored | **LakshmanRekha shield** — injection, credential, exfil detection on every tool call | PreToolUse hook logs |
| CC7.2 — Anomalies are identified and communicated | **Anomaly detection** — cost rate spikes, night-time activity, runaway sessions | Dashboard alerts panel + `~/.aegis/aegis.db` alerts table |
| CC7.3 — Security incidents are evaluated | **KAVACH audit trail** — every interception logged with command, level, decision, approver | `SELECT * FROM kavach_approvals` |
| CC7.4 — Incidents are contained | **Kill-switch** — `aegis kill` SIGKILL/SIGSTOP in <1s | `aegis kill` command |

### CC8 — Change Management

| SOC 2 Criterion | AEGIS Control | Evidence |
|---|---|---|
| CC8.1 — Infrastructure changes are controlled | **KAVACH DAN Gate** — L1–L4 approval required before destructive infrastructure commands | `kavach_approvals` table, `decided_by` field |

### CC9 — Risk Mitigation

| SOC 2 Criterion | AEGIS Control | Evidence |
|---|---|---|
| CC9.1 — Risk assessment identifies threats from agents | **HanumanG 7-axis check** — delegation depth, budget inheritance, identity confidence | `aegis check-spawn` logs |
| CC9.2 — Vendor/third-party risk is managed | **Budget caps** — hard limits prevent runaway API spend across vendors | `~/.aegis/config.json` budget section |

### A1 — Availability

| SOC 2 Criterion | AEGIS Control | Evidence |
|---|---|---|
| A1.2 — Processing is authorized and complete | **Budget caps + spawn governance** — prevents resource exhaustion from runaway agents | `budget_state` table |
| A1.3 — Monitoring detects threats to availability | **Watchdog daemon** — zombie/orphan detection, velocity throttle, cost rate anomaly | `aegis-watchdog` logs |

---

## Audit Evidence Package

For a SOC 2 audit involving AI agents, collect:

```bash
# 1. KAVACH approval log — all interceptions with decisions
sqlite3 ~/.aegis/aegis.db "SELECT * FROM kavach_approvals ORDER BY created_at DESC"

# 2. Agent state log — lifecycle transitions
sqlite3 ~/.aegis/aegis.db "SELECT agent_id, state, quarantine_reason, decided_by FROM agents"

# 3. Budget state — limits and spend
sqlite3 ~/.aegis/aegis.db "SELECT * FROM budget_state ORDER BY period"

# 4. Alert log — anomalies and incidents
sqlite3 ~/.aegis/aegis.db "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 100"

# 5. Policy files — per-agent perm_mask and class_mask
ls ~/.aegis/agents/
cat ~/.aegis/agents/{agent-id}.policy.json

# 6. Config — budget limits and enforcement mode
cat ~/.aegis/config.json
```

---

## Limitations

AEGIS does not:
- Provide network-level access controls (complement with firewall/VPC rules)
- Log agent outputs or LLM responses (complement with your AI provider's audit logs)
- Enforce identity federation (complement with IAM/SSO for human approvers)
- Guarantee real-time alerting delivery (Telegram/WhatsApp delivery is best-effort)

---

## Document status

This is a reference template. Customize for your organization's specific SOC 2 scope, control objectives, and auditor requirements.

Version: AEGIS 1.0.0 | Date: 2026-04-29 | License: AGPL-3.0
