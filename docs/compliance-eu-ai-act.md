# AEGIS — EU AI Act Article 14 Human Oversight Compliance Reference

> This document maps AEGIS controls to the human oversight requirements under the EU AI Act (Regulation (EU) 2024/1689), primarily Article 14. Use as a reference when operating high-risk AI systems subject to the Act.

---

## Scope

**Article 14 applies to:** High-risk AI systems as defined in Annex III of the EU AI Act, including AI used in critical infrastructure, employment decisions, access to education, and law enforcement contexts. Agentic AI systems with autonomous decision-making capability may fall under high-risk classification.

**What AEGIS addresses:** Article 14 requires that high-risk AI systems be designed to allow natural persons to effectively oversee operation during use. AEGIS implements technical controls that make this oversight possible.

---

## Article 14 Requirements and AEGIS Controls

### Art. 14(1) — Effective oversight by natural persons

> "High-risk AI systems shall be designed and developed in such a way, including with appropriate human-machine interface tools, that they can be effectively overseen by natural persons during the period in which the AI system is in use."

**AEGIS control:** The KAVACH DAN Gate intercepts destructive commands before execution and routes approval to a human via Telegram, WhatsApp, or dashboard. No irreversible action runs without explicit human decision.

**Evidence:** `kavach_approvals` table — `decided_by`, `status`, `decided_at` fields per interception.

---

### Art. 14(2) — Oversight measures during deployment

> "Oversight measures shall be commensurate with the risks, autonomy and operating context of the high-risk AI system."

**AEGIS control:** Four-level DAN Gate (L1–L4) maps oversight intensity to risk level:
- L1/L2: Operator can override with `# AEGIS-DESTRUCTIVE-CONFIRMED` token
- L3: Human approval required via notification channel
- L4: Dual-control — two separate human approvals required

**Evidence:** `gate.ts` LEVEL_RULES classification + `config.json` dual_control_enabled flag.

---

### Art. 14(3)(a) — Understand system capabilities and limitations

> "The measures referred to in paragraph 1 shall enable the persons to whom human oversight is assigned to [...] fully understand the capacities and limitations of the high-risk AI system."

**AEGIS control:** 
- `aegis status` shows current budget state, active sessions, agent spawn depth
- Dashboard provides real-time visibility: cost rate, token velocity, spawn tree
- Each KAVACH notification includes plain-English consequence description of the intercepted action

**Evidence:** Dashboard at `http://localhost:4850`, `aegis status` output, notification text format.

---

### Art. 14(3)(b) — Remain aware of automation bias

> "[...] remain aware of the possible tendency to automatically over-rely on or follow the output produced by the high-risk AI system ('automation bias')."

**AEGIS control:** Silence-equals-STOP default. The DAN Gate does not default to ALLOW on timeout — it requires an explicit positive decision. This prevents automation bias from manifesting as passive acceptance.

**Evidence:** `gate.ts` `pollForDecision()` — timeout returns `"TIMEOUT"` → `STOP`, not `ALLOW`.

---

### Art. 14(3)(c) — Correctly interpret output

> "[...] be able to correctly interpret the AI system's output, taking into account, in particular, the characteristics of the system and the tools available to it."

**AEGIS control:** KAVACH notification includes:
- The literal command the agent wants to run
- The plain-English consequence (blast radius)
- The severity level with label
- Time remaining before default-safe timeout

**Evidence:** `buildNotificationMessage()` in `gate.ts` — consequence field, level label.

---

### Art. 14(3)(d) — Decide not to use or override

> "[...] be able to decide, in any particular situation, not to use the high-risk AI system or to override, correct, correct or disregard its output."

**AEGIS control:** 
- STOP decision blocks the action immediately
- `aegis kill` / `aegis kill --stop` halts all agent processes at any time
- `enforcement.mode: "alert"` vs `"enforce"` gives operators control over automated enforcement level

**Evidence:** `kill.ts` command, `check-budget.ts` enforcement mode check.

---

### Art. 14(3)(e) — Intervene on operation

> "[...] be able to intervene on the operation of the high-risk AI system or interrupt the system through a stop button or similar procedure."

**AEGIS control:** 
- `aegis kill` — SIGKILL all agent processes (< 1 second)
- `aegis kill --stop` — SIGSTOP (pause, resumable with `aegis resume`)
- Dashboard KILL ALL / PAUSE ALL buttons
- KAVACH STOP decision via Telegram/WhatsApp reply

**Evidence:** `kill.ts`, `resume.ts`, dashboard controls panel.

---

## Art. 14(4) — Deployment-specific oversight measures

> "For providers of high-risk AI systems that are AI systems referred to in Article 6(2) [...] the human oversight measures referred to in paragraph 3 shall ensure that no action or decision is taken by the deployer on the basis solely of the output of the high-risk AI system unless it has been reviewed and validated by a natural person."

**AEGIS control:** The KAVACH DAN Gate enforces this at the execution boundary. No destructive action executes without human validation. The `decided_by` field records which human validated each action.

---

## Implementation Checklist

For organizations deploying agentic AI systems under Art. 14:

- [ ] AEGIS installed and `aegis init` run on all AI agent hosts
- [ ] `enforcement.mode: "enforce"` enabled (auto-kill on budget breach)
- [ ] KAVACH Telegram/WhatsApp notification channel configured
- [ ] L4 dual-control enabled for irreversible infrastructure operations (`dual_control_enabled: true`)
- [ ] Dashboard accessible to oversight personnel (`http://localhost:4850` or secured proxy)
- [ ] Audit export procedure documented (SQLite query commands)
- [ ] Incident response procedure documents `aegis kill` as the stop button
- [ ] Oversight personnel trained to respond to KAVACH notifications within timeout window

---

## Limitations

AEGIS does not:
- Classify AI systems as high-risk or low-risk under Annex III (legal determination required)
- Substitute for a conformity assessment or CE marking
- Provide data governance controls beyond audit logging
- Cover the full scope of the EU AI Act (only Art. 14 oversight controls)

Legal advice is required to determine whether your specific AI system deployment constitutes a high-risk AI system under the Act.

---

## Document status

This is a reference template. Customize for your organization's specific deployment scope and regulatory counsel's guidance.

Version: AEGIS 1.0.0 | Date: 2026-04-29 | License: AGPL-3.0
