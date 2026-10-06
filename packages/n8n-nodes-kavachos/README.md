# @xshieldai/n8n-nodes

> **🔍 Verification status (2026-10-05 IST — v1.1.2)**
> - **Tests:** ⚠️ none yet — n8n node test fixtures planned. See [PROOF-STACK.md](https://github.com/rocketlang/aegis/blob/master/PROOF-STACK.md).
> - **Examples:** ✅ 1 importable workflow, in the repository (not in the npm package): [examples/n8n-governed-agent.json](https://github.com/rocketlang/aegis/blob/master/packages/n8n-nodes-kavachos/examples/n8n-governed-agent.json). Drag into n8n, wire the Aegis API credential pointing at `http://localhost:4850`, run.
> - **Live demo:** ⚠️ planned (Tier 3)
> - **Phase-1 limits:** KavachRun is Linux-only; where enforcement is unavailable (non-Linux, or `kavachos` not installed) it **fails closed by default** (`On Non-Linux` = `throw`; `warn`/`skip` are opt-in). KavachGate works on any OS — it's a thin HTTP relay to AEGIS.
>
> The KavachGate node's behaviour is end-to-end testable against a live AEGIS instance — start AEGIS, import the example workflow, fire a `rm -rf /` command, watch it block. Automated CI fixtures still to come.

**KavachOS n8n community nodes** — pre-execution DAN gate and kernel enforcement for AI agents.

Part of the **xShieldAI Posture Suite** · [kavachos.xshieldai.com](https://kavachos.xshieldai.com)

---

## Nodes

### KavachGate

Intercepts AI agent actions **before execution**. Calls the Aegis KAVACH HTTP gate to:

1. Classify danger level (DAN 1–4)
2. Notify approvers via Telegram / WhatsApp (opt-in, requires `webhook_url` in `~/.aegis/config.json`)
3. Wait for ALLOW or STOP
4. Block the workflow on STOP or timeout (silence = STOP)

**Framework-neutral**: all policy lives in Aegis (`localhost:4850`). The n8n node is a thin HTTP client.

### KavachRun

Wraps a subprocess in kavachos **kernel enforcement** (seccomp-bpf + cgroup BPF egress firewall).

- Linux only — where enforcement is unavailable it **fails closed by default** (`On Non-Linux` = `throw`; set `warn` to run unwrapped, or `skip`)
- Use **after** KavachGate for defense in depth: policy gate + kernel enforcement
- `trust_mask` controls which syscall groups the process may call
- `domain` selects the egress allowlist (maritime, logistics, OT, finance, general)

---

## Install

```bash
# In your n8n data directory
npm install @xshieldai/n8n-nodes
```

Then restart n8n and add the **Aegis API** credential pointing to your Aegis dashboard (`http://localhost:4850` by default).

---

## Quick Start

1. **Start Aegis**: `npx @xshieldai/aegis` (or `kavachos run n8n --domain=general`)
2. **Add credential**: Aegis API → base URL `http://localhost:4850`
3. **Import template**: `examples/n8n-governed-agent.json`
4. **Run**: Trigger → KavachGate → AI Agent → Audit

---

## Gate API

The `KavachGate` node calls:

```
POST http://localhost:4850/api/v1/kavach/gate
{ "command": "...", "tool_name": "n8n-agent", "session_id": "...", "dry_run": false }

→ { "allow": true|false, "level": 0-4, "reason": "...", "decision": "ALLOW|STOP|TIMEOUT", "approval_id": "...", "_meta": {...} }
```

`allow: false` → KavachGate throws (halt workflow) or passes `allow=false` downstream — configurable per node.

---

## License

AGPL-3.0 — governance layer is open. Enterprise Edition (multi-tenant, Merkle ledger, EU AI Act evidence): [xshieldai.com](https://xshieldai.com)
