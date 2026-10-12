# @xshieldai/n8n-nodes-kavachos

> **🔍 Verification status (2026-10-12 IST — v1.5.2)**
> - **Tests:** ⚠️ none inside the package. In the repository: [red-team/n8n-kavach-run.battery.sh](https://github.com/rocketlang/aegis/blob/master/red-team/n8n-kavach-run.battery.sh) drives the Run and Gate nodes outside n8n against an installed copy (35 cases), and [red-team/n8n-inside-n8n.battery.sh](https://github.com/rocketlang/aegis/blob/master/red-team/n8n-inside-n8n.battery.sh) installs the package through n8n's own installer and runs all four nodes in workflows inside n8n 2.42.7 (23 cases; first run on 1.5.1, 12 October 2026). Gate, Budget and Audit run against a real Aegis there. **Kavach Run is tested with a stand-in `kavachos` in both: neither battery launches anything under kernel enforcement.**
> - **Examples:** ✅ 1 importable workflow, in the repository (not in the npm package): [examples/n8n-governed-agent.json](https://github.com/rocketlang/aegis/blob/master/packages/n8n-nodes-kavachos/examples/n8n-governed-agent.json). Drag into n8n, wire the Aegis API credential pointing at `http://localhost:4850`, run.
> - **Live demo:** ⚠️ planned (Tier 3)
> - **Phase-1 limits:** KavachRun is Linux-only; where enforcement is unavailable (non-Linux, or `kavachos` not installed) it **fails closed by default** (`On Non-Linux` = `throw`; `warn`/`skip` are opt-in). KavachGate works on any OS — it's a thin HTTP relay to AEGIS.
>
> The KavachGate node's behaviour is end-to-end testable against a live AEGIS instance — start AEGIS, import the example workflow, fire a `rm -rf /` command, watch it block.

> **Renamed at 1.5.0.** This package was `@xshieldai/n8n-nodes` through 1.4.1. n8n's community-nodes screen
> only installs a package whose name starts with `n8n-nodes-` after the scope, and refused the old name. The
> nodes are the same. A workflow saved with the old package names its nodes `@xshieldai/n8n-nodes.kavachGate`
> and so on: after installing this package, change that prefix to `@xshieldai/n8n-nodes-kavachos.` in the
> workflow (or re-add the nodes), and remove the old package.

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

**Requires `@xshieldai/agent-kernel` 2.5.0 or later** (since 1.3.0). The node starts
`kavachos run <options> -- <binary> <arguments>`, so the binary's arguments are passed on word for word and
cannot be read as kavachos options. With an older `kavachos` the node refuses to run. See the changelog.

Since 1.5.2 an argument in quotes is one word: `--name 'two words'`. Nothing else in the **Arguments** field is
read specially (it is not a shell), and a quote that is never closed stops the node before anything runs.

Since 1.4.0 the node waits for the command without stopping n8n, stops it at **Time Limit (seconds)**, and
reports what `kavachos` itself said: a refused launch is an error, and `enforced` is true only when no layer
was reported missing (`egress_constrained`, `path_jail_loaded`). It reads kavachos's own lines for this, so
it is as true as they are.

**This node runs a command on the n8n host.** Anyone who can edit a workflow that contains it can run a
program there, as n8n's own Execute Command node can. Install it only where that is acceptable.

- Linux only — where enforcement is unavailable it **fails closed by default** (`On Non-Linux` = `throw`; set `warn` to run unwrapped, or `skip`)
- Use **after** KavachGate for defense in depth: policy gate + kernel enforcement
- `trust_mask` controls which syscall groups the process may call
- `domain` selects the egress allowlist (maritime, logistics, OT, finance, general)

---

## Install

```bash
# In your n8n data directory
npm install @xshieldai/n8n-nodes-kavachos
```

Then restart n8n and add the **Aegis API** credential pointing to your Aegis dashboard (`http://localhost:4850` by default).

---

## Quick Start

1. **Start Aegis**: `npx @xshieldai/aegis` (or `kavachos run --domain=general -- n8n`)
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
