# @xshieldai/agent-kernel

> **🔍 Verification status (2026-05-17 IST)**
> - **Tests:** ⚠️ none in OSS dist. The full internal `kavachos-ee` service has its own test suite covering seccomp-bpf profile generation, BPF egress firewall, and Falco rule synthesis — those tests are not currently distributed with this package.
> - **Examples:** 📄 CLI quick-start in this README is runnable on Linux x86_64 (kernel ≥ 3.5 for seccomp-bpf, ≥ 5.8 for Falco modern-bpf). Try: `kavachos generate --trust-mask=0xFF --domain=maritime --json` (no exec, just inspect the generated profile).
> - **Live demo:** ⚠️ planned (Tier 3)
> - **Phase-1 limits:** Linux x86_64 only. macOS/Windows degrade gracefully via the n8n nodes' `fallback` setting but the CLI requires Linux.
>
> The kernel-enforcement primitives (seccomp-bpf default-deny, exit_group/futex/rt_sigreturn always allowed, cgroup BPF connect4/connect6 hooks) match the [KavachOS Protocol paper](https://doi.org/10.5281/zenodo.19908430). OSS-package-level test artifact lands in v2.1.0.

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

## State roots

The kernel reads its declarations from three roots. They default to ANKR's own layout;
set these to run anywhere else:

| variable | default | holds |
|---|---|---|
| `ANKR_CONFIG_DIR` | `/root/.ankr/config` | `databases.json`, `ports.json` |
| `ANKR_STATE_DIR` | `/root/.ankr/state` | session and edit ledgers |
| `AEGIS_HOME` | `/root/.aegis` | mode, seal, taint, compiled policy |

Relocating a root is deliberately **not silent**. These files are the instruments the
permissive layer reads its verdicts from, so whoever chooses where they live has chosen
what the layer reads. Every refusal and every compiled policy states when a root is not
the default, and the override is part of the policy digest.


## The AEGIS / KavachOS / PRAMANA stack

Three layers. One coherent governance stack for agentic AI.

| Layer | Package | What it governs |
|-------|---------|-----------------|
| **AEGIS** | [`@rocketlang/aegis`](https://www.npmjs.com/package/@rocketlang/aegis) | Agent **spend** — budget caps, spawn governance, cross-surface usage visibility, kill-switches |
| **KavachOS** | `@xshieldai/agent-kernel` (this package) | Agent **behavior** — syscall mediation, exec allowlist, egress firewall, sandboxed runtime |
| **PRAMANA** | DOI [10.5281/zenodo.19273330](https://doi.org/10.5281/zenodo.19273330) | Cryptographic **attestation** — tamper-evident chain of every decision either layer made |

AEGIS governs what the agent spends. KavachOS governs what the agent does. PRAMANA proves what happened.

For EU AI Act Article 14 (human oversight): PRAMANA alone is just logging — it proves what happened but doesn't prevent the next bad thing. KavachOS alone is just enforcement — it gates behavior but leaves no verifiable trail. Together: the human can override (HITL gate), and the override is recorded in a tamper-evident chain. KavachOS is the airbag. PRAMANA is the black box. Article 14 requires both.

---

## Install

```bash
npm install -g @xshieldai/agent-kernel
# or
bun add -g @xshieldai/agent-kernel
```

Requires: **Bun ≥ 1.0**, **Linux x86_64**, kernel ≥ 3.5 (seccomp-bpf), kernel ≥ 5.8 for Falco modern-bpf.

---

## Quick start

```bash
# Initialize project config
kavachos init --domain=general --trust-mask=0xFF

# Run any agent under kernel enforcement
kavachos run --trust-mask=0xFF --domain=general --verbose -- claude

# Run a Bun script with maritime domain rules
kavachos run --trust-mask=0x00FF0000 --domain=maritime --falco -- bun src/my-agent.ts --port 4900

# Inspect profile + gate valve state
kavachos profile show

# Audit the receipt chain
kavachos audit --all
```

### `--` ends kavachos's options (2.5.0)

Write kavachos's options first, then a bare `--`, then the agent's command. Everything after `--` is passed
to the agent word for word and is never read as a kavachos option.

Through 2.4.0 every word starting with `--` was read as a kavachos option wherever it stood on the line, and
removed from what the agent received. So the agent lost its own options (`--port` above), and whoever supplied
the agent's arguments could set kavachos's: `--dry-run` (nothing runs, exit 0), `--allow-unconstrained-egress`,
`--needs=`, `--depth=`, `--session-id=`, a trust mask if none was given.

A line without `--` is still read the old way, so existing launch lines keep working; each option found after
the agent's binary is named in a warning on stderr. **From 3.0 a line without `--` will be refused**: while the old
reading remains, a caller who forgets `--` is still exposed, so it is kept for one major version only. **If the agent's arguments come from anywhere but your own
hand (a workflow, a wrapper script, a model), use `--`.** A dry run now also prints the command that would be
launched and the choices it would be launched under. Found in our own review, not reported from outside.
Checked by `red-team/kavachos-run-args.battery.sh` in the repository (dry runs only): 7 gaps on 2.4.0, none on 2.5.0.

### The proxy is trusted by its certificate (2.6.0)

`kavachos proxy start` terminates TLS with a self-signed certificate. Through 2.5.0:

- an agent launched with `KAVACHOS_PROXY_URL` set was given `NODE_TLS_REJECT_UNAUTHORIZED=0` and
  `PYTHONHTTPSVERIFY=0`. That switched certificate checking off for **every** host the agent talked to, not
  only the proxy;
- the certificate and its key were two fixed names in `/tmp`, reused if already there, so whoever wrote those
  files first held the proxy's key;
- the proxy listened on every interface;
- the certificate named no host, so a client could not verify it even when told to trust it.

From 2.6.0:

- the pair is made fresh on every proxy start, under `<aegis home>/kernel/proxy/` (folder `700`, key `600`),
  valid 30 days, naming `localhost` and `127.0.0.1`. **Restart the proxy at least every 30 days**;
- `kavachos run` hands the agent that one certificate as an extra trust root (`NODE_EXTRA_CA_CERTS` for Node
  and Bun; `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` and `CURL_CA_BUNDLE` pointing at the system's roots plus this
  certificate, for Python and curl). Checking stays on. If the certificate cannot be found the agent's calls
  to the proxy fail, and the launcher says why;
- the proxy listens on `127.0.0.1` unless `--host=` or `KAVACHOS_PROXY_HOST` says otherwise;
- start the proxy and the agent as the same account (or name the certificate with `KAVACHOS_PROXY_CA`).

**What this does not give.** The agent runs as the account that owns the key file; the AppArmor profile in the
repository now denies it that file, but without the profile loaded an agent can read it. The proxy still lets
a request through when it cannot reach the budget service; that is its stated design, not changed here.
Found in our own review, not reported from outside. Checked by `red-team/kavachos-proxy-trust.battery.sh`
(10 cases, no launch under enforcement): 9 gaps on 2.5.0, none on 2.6.0.

### The package holds the files its code reaches for (2.6.1)

Through 2.6.0 this package left out `dns-proxy.py`, which the egress supervisor loads from beside itself, and
the AppArmor profile with its install script. Without the first, the supervisor leaves name lookups denied:
an agent under egress enforcement could resolve nothing (read from the code, not watched in a run). The
launcher's warning about the path jail named a path that exists only in the source repository.

2.6.1 ships all three under `dist/`, and the warning names the script where it is installed
(`…/node_modules/@xshieldai/agent-kernel/dist/apparmor/install.sh`, run as root). The profile is written for a
root home; on another account edit its paths first.


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
