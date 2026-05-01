# @rocketlang/kavachos

**KavachOS** — seccomp-bpf + Falco kernel enforcement for AI agents.

Part of the **xShieldAI Posture Suite** · [kavachos.xshieldai.com](https://kavachos.xshieldai.com)

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%203.0-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.19908430.svg)](https://doi.org/10.5281/zenodo.19908430)

---

## What it does

KavachOS wraps every AI agent in a seccomp-bpf kernel filter. The agent can only make the syscalls its trust level permits — nothing else reaches the kernel.

- **seccomp-bpf profiles** generated deterministically from a `trust_mask` integer
- **cgroup BPF egress firewall** — per-session network allowlist enforced at the kernel connect4/connect6 hook; unlisted destinations get `EPERM` before the socket is established
- **Falco rules** generated per domain (maritime, logistics, OT, finance, general)
- **PRAMANA receipt chain** — every violation is SHA-256 sealed and chained
- **Gate valve** — automatic escalation: THROTTLE → CRACK → LOCK on repeated violations
- **CLI** — `kavachos run`, `kavachos profile show`, `kavachos audit`, `kavachos init`

```
defaultAction: SCMP_ACT_ERRNO   ← blocked syscall returns EPERM, never panics kernel
exit_group + futex + rt_sigreturn always allowed  ← no-freeze guarantee
```

---

## The AEGIS / KavachOS / PRAMANA stack

Three layers. One coherent governance stack for agentic AI.

| Layer | Package | What it governs |
|-------|---------|-----------------|
| **AEGIS** | [`@rocketlang/aegis`](https://www.npmjs.com/package/@rocketlang/aegis) | Agent **spend** — budget caps, spawn governance, cross-surface usage visibility, kill-switches |
| **KavachOS** | `@rocketlang/kavachos` (this package) | Agent **behavior** — syscall mediation, exec allowlist, egress firewall, sandboxed runtime |
| **PRAMANA** | DOI [10.5281/zenodo.19273330](https://doi.org/10.5281/zenodo.19273330) | Cryptographic **attestation** — tamper-evident chain of every decision either layer made |

AEGIS governs what the agent spends. KavachOS governs what the agent does. PRAMANA proves what happened.

For EU AI Act Article 14 (human oversight): PRAMANA alone is just logging — it proves what happened but doesn't prevent the next bad thing. KavachOS alone is just enforcement — it gates behavior but leaves no verifiable trail. Together: the human can override (HITL gate), and the override is recorded in a tamper-evident chain. KavachOS is the airbag. PRAMANA is the black box. Article 14 requires both.

---

## Install

```bash
npm install -g @rocketlang/kavachos
# or
bun add -g @rocketlang/kavachos
```

Requires: **Bun ≥ 1.0**, **Linux x86_64**, kernel ≥ 3.5 (seccomp-bpf), kernel ≥ 5.8 for Falco modern-bpf.

---

## Quick start

```bash
# Initialize project config
kavachos init --domain=general --trust-mask=0xFF

# Run any agent under kernel enforcement
kavachos run claude --trust-mask=0xFF --domain=general --verbose

# Run a Bun script with maritime domain rules
kavachos run bun src/my-agent.ts --trust-mask=0x00FF0000 --domain=maritime --falco

# Inspect profile + gate valve state
kavachos profile show

# Audit the receipt chain
kavachos audit --all
```

---

## Commands

| Command | Description |
|---------|-------------|
| `kavachos run <binary> [args]` | Launch agent under seccomp-bpf governance |
| `kavachos generate` | Generate profile + Falco rules (no exec) |
| `kavachos profile show [agent-id]` | Show active profile + gate valve state |
| `kavachos audit [session-id\|--all]` | Verify PRAMANA receipt chain |
| `kavachos rules` | Print domain-specific Falco rules |
| `kavachos init` | Write `.kavachos.json` in project root |

---

## trust_mask

Each bit unlocks a syscall group. `trust_mask=0` → read-only minimal profile.

```
Bits 0-7   Infrastructure: auth | rbac | events | db | notification | cache | registered | forja
Bits 8-15  Intelligence:   llm  | knowledge | domain_rules | memory | search | packages | swarm | codegen
```

```bash
kavachos generate --trust-mask=0xFF --domain=maritime --json
```

---

## Domain profiles

| Domain | Extra rules |
|--------|-------------|
| `general` | Baseline only |
| `maritime` | NMEA serial ops, AIS monitoring |
| `logistics` | EDI file processing |
| `ot` | Modbus TCP, realtime scheduling |
| `finance` | HSM / hardware key ops |

---

## License

AGPL-3.0 — kernel enforcement layer is open. You can audit what runs next to your production agents.

Enterprise Edition (multi-tenant, HanumanG EE, Merkle ledger, EU AI Act evidence): [xshieldai.com](https://xshieldai.com)

---

## Papers

- KavachOS Protocol: [10.5281/zenodo.19908430](https://doi.org/10.5281/zenodo.19908430)
- PRAMANA Receipt Chain: [10.5281/zenodo.19273330](https://doi.org/10.5281/zenodo.19273330)
