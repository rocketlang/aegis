# AEGIS

> **Can you answer what your agents touched?** AEGIS makes that one command — and stops the answer from ever being "we don't know."

[![npm version](https://img.shields.io/npm/v/@xshieldai/aegis.svg)](https://www.npmjs.com/package/@xshieldai/aegis)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.19625473.svg)](https://doi.org/10.5281/zenodo.19625473)
[![CI](https://github.com/rocketlang/aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/rocketlang/aegis/actions/workflows/ci.yml)
[![Security](https://img.shields.io/badge/trust-audit%20us-green)](SECURITY.md)

**AEGIS** (Agentic Execution Governance & Intelligence System) is a vendor-neutral kill-switch for AI agents. Works with Claude Code, OpenAI Codex, Cursor, and any tool that writes session logs or makes API calls.

Born on **17 April 2026** from a real $200 incident: a user stopped using Claude Code, walked away, came back to find their weekly Max Plan fully exhausted with no visibility into what ran.

## Answerability first

When an autonomous agent swarm attacks a public registry and its operator cannot tell, from its own logs, what its agents touched — that is not a logging gap, it is a missing capability. AEGIS builds it in:

```bash
aegis touched --since 7d        # per principal: refused, observed, published-under-which-
                                # mandate, tripwire tells, receipt hash-chain verified
aegis rehearse-chain            # walk the incident chain against your own gates —
                                # every step must refuse or alert; digest-sealed evidence pack
aegis quarterly-report --prev last.json   # the period report + what changed since
```

Three properties back it, each honest about its stage (shadow ≠ blocked, and the output says which):

1. **A permissive layer between the agent and the world** — unknown state refuses; production-target writes are judged by the *resolved target*, not the command text. New invariants enter in shadow and are promoted only on ledger evidence.
2. **Publishing is a mandate, never a side effect** — `aegis publish-mandate` grants named, time-bounded consent; every publish attempt leaves a provenance record; undeclared CI publish steps fail the build (`aegis ci-audit`).
3. **Answerability as a capability** — one command over tamper-evident ledgers, with the ceiling stated: host-computed evidence survives a lying agent, not a compromised host, and an empty report means nothing *ledgered*, never "nothing happened."

---

## ⚠️ Package rename (2026-05-17) — `@rocketlang/*` → `@xshieldai/*`

Same code, new home. As of v2.2.0 the AEGIS / Agent Kernel / primitive packages publish under the **xShieldAI Posture Suite** umbrella:

| Old | New |
|---|---|
| `@rocketlang/aegis` | `@xshieldai/aegis` |
| `@rocketlang/kavachos` | `@xshieldai/agent-kernel` |
| `@rocketlang/n8n-nodes-kavachos` | `@xshieldai/n8n-nodes` |
| `@rocketlang/aegis-guard` | `@xshieldai/aegis-guard` |
| `@rocketlang/chitta-detect` | `@xshieldai/chitta-detect` |
| `@rocketlang/lakshmanrekha` | `@xshieldai/lakshmanrekha` |
| `@rocketlang/hanumang-mandate` | `@xshieldai/hanumang-mandate` |
| `@rocketlang/aegis-suite` | `@xshieldai/aegis-suite` |
| `langchain-kavachos` (PyPI) | `xshieldai-langchain` (PyPI) |
| `crewai-kavachos` (PyPI) | `xshieldai-crewai` (PyPI) |

Old packages are **deprecated on npm** with redirect messages. Existing installs keep working; please migrate on next `npm update` or `pip install`. See **[MIGRATION.md](MIGRATION.md)** for one-line migrations.

---

## 🔍 Verification status (2026-05-17 IST)

Security tooling without proof is just marketing. The honest current state of `@xshieldai/aegis` v2.7.0:

- **Tests:** 📄 1088 passing in the repository (`bun test src/ tests/`), and the dashboard + kill switch are exercised live on a socket in [`tests` + the atma-pariksha batteries]. For the budget and spawn hooks: 19 in [`tests/budget-spawn-hardening.test.ts`](tests/budget-spawn-hardening.test.ts), driven on a socket as a harness drives them. For the destructive-command gate: 104 in [`tests/destructive-hardening.test.ts`](tests/destructive-hardening.test.ts). For the shield hook: 23 in [`src/shield/shield.test.ts`](src/shield/shield.test.ts) and 165 in [`src/shield/hardening.test.ts`](src/shield/hardening.test.ts) — path rules, credential reads and persistence writes through a shell command, the shield's own files, network tools, phrase variants, answer time, and the stated limits. What the shield does not see is listed under "What the shield stops, and what it does not" below.
- **Examples:** 📄 `examples/agents/` — Claude Code + OpenAI Codex hooks. Plus the README "Verify it yourself" `grep` commands in the **Trust** section below are runnable proof of zero phone-home.
- **Live demo:** ✅ **PUBLIC at https://xshieldai.com/demo** — paste text → pick primitive → see verdict + live receipt in the stream below. 4 primitives invokable, SSE streaming through Cloudflare, per-visitor rate-limited (30 req/min). Also available locally at `http://localhost:4850/demo` when `ankr-aegis-dashboard` runs.
- **Forja receipt stream:** ⚠️ planned (Tier 4 — "binary truth, not interpretation" answer).

The **bundled primitives** (`@xshieldai/aegis-guard`, `chitta-detect`, `lakshmanrekha`, `hanumang-mandate`, `agent-kernel`) each have their own verification banner. Full per-package matrix: **[PROOF-STACK.md](PROOF-STACK.md)**.

`aegis-guard` has 63 passing tests today (the Five Locks SDK extracted from carbonx-backend). The other 3 primitives ship code-only this week; their v0.2.1 patches add ~30 tests each.

This banner exists because *"how do I know it does what it claims?"* is the right question for security tooling. We'd rather under-claim with proof than over-claim with vibes.

---

## The AEGIS / KavachOS / PRAMANA stack

Three layers. One coherent governance stack for agentic AI.

| Layer | Package | What it governs |
|-------|---------|-----------------|
| **AEGIS** | `@xshieldai/aegis` (this package) | Agent **spend** — budget caps, spawn governance, cross-surface usage visibility, kill-switches |
| **KavachOS** | [`@xshieldai/agent-kernel`](https://www.npmjs.com/package/@xshieldai/agent-kernel) | Agent **behavior** — syscall mediation, exec allowlist, egress firewall, sandboxed runtime |
| **PRAMANA** | DOI [10.5281/zenodo.19273330](https://doi.org/10.5281/zenodo.19273330) | Cryptographic **attestation** — tamper-evident chain of every decision either layer made |

AEGIS governs what the agent spends. KavachOS governs what the agent does. PRAMANA proves what happened.

For EU AI Act Article 14 (human oversight): PRAMANA alone is just logging — it proves what happened but doesn't prevent the next bad thing. AEGIS + KavachOS alone are just enforcement — they gate behavior but leave no verifiable trail. Together: the human can override (HITL gate), and the override is recorded in a tamper-evident chain. KavachOS is the airbag. PRAMANA is the black box. Article 14 requires both.

---

## Install in 3 steps

```bash
# 1. Install
npm install -g @xshieldai/aegis

# 2. Initialize (wires hooks into Claude Code automatically)
aegis init

# 3. Check status
aegis status
```

That's it. AEGIS is now watching every tool call.

---

## What it does — the KAVACH DAN Gate

Before any destructive command runs, AEGIS intercepts it and asks you:

```
🔴 KAVACH — Action Requires Approval

  Agent wants to run:
  `prisma migrate reset --force`

  Consequence:
  This will permanently destroy an entire database or critical system
  directory. All data will be unrecoverable. Blast radius: CRITICAL.

  Level: L4 — Irreversible + High blast radius

  Reply with one word:
    STOP  — block this action
    ALLOW — permit this action

  Approval ID: KAVACH-3F9A1C4B
  Expires: 1 min  (silence = STOP)
  Dashboard: http://localhost:4850
```

The message lands on your Telegram or WhatsApp. Reply `STOP` or `ALLOW`. If you ignore it, the action is **blocked by default**. The agent waits. Nothing runs until you decide.

Four severity levels:
- **L1** — Recoverable with effort (DELETE FROM, git reset --hard)
- **L2** — Hard to recover (DROP TABLE, rm -rf)
- **L3** — Irreversible (DROP SCHEMA, docker compose down -v, git push --force main)
- **L4** — Irreversible + catastrophic blast (DROP DATABASE, prisma migrate reset)

---

## Trust

> KAVACH sits between your AI agent and your infrastructure. You should not trust it blindly — including this build.

| What KAVACH does | What KAVACH does NOT do |
|---|---|
| Stores approval records in **local SQLite** (`~/.aegis/`) | Send your commands to any remote server |
| Sends the intercepted command to **your** Telegram/WhatsApp | Phone home on every gate check |
| Serves a dashboard on **localhost** only | Include analytics SDKs or background beacons |
| Fires one opt-in beacon on `aegis init --send-stats` | Make any network call without your consent |

**Verify it yourself:**
```bash
grep -rn "fetch(" src/              # every outbound call — all documented in SECURITY.md
grep -rn "kavach.xshieldai" src/    # beacon — only in init.ts, only on --send-stats
grep -rn "webhook_url\|registry_url" src/  # all user-configured endpoints
```

**AGPL-3.0:** Any modified version run as a service must publish source. A backdoor would be visible in the diff.

→ Full trust documentation: [SECURITY.md](SECURITY.md)

---

## The Problem

In traditional software:
```
You stop → System stops
```

In agentic AI:
```
You stop → System might continue
         → Agents might spawn more agents
         → Cost accumulates without awareness
         → No mechanism detects "the human left"
```

Multiple surfaces (CLI + web + mobile + API) all consume from the same budget. None shows the other's usage. One instruction can become 200+ agent spawns silently. There's no unified kill-switch.

**If an agent can execute without you, it can also spend without you.**

---

## What AEGIS Provides

### Six capabilities

| # | Capability | What it does |
|---|------------|--------------|
| 1 | **KAVACH Gate** | PreToolUse hook intercepts destructive commands before execution. By default it refuses at once and a person approves one command with `aegis approve-destructive`; switched on, it asks a person over Telegram/WhatsApp or the dashboard and waits |
| 2 | **Unified Usage Dashboard** | All surfaces, all sessions, all spend — one real-time view with KAVACH approvals panel |
| 3 | **Hard Budget Caps** | Per session, per 5h window, per day/week — tiered warnings at 80%/90%/100% |
| 4 | **Kill-Switch** | `aegis kill` sends SIGKILL/SIGSTOP to all agent processes in under 1 second |
| 5 | **Agent Spawn Governance** | Block subagent spawns above a configurable limit per session |
| 6 | **Anomaly Detection** | Alert on spend spikes, night-time activity, runaway sessions |

### Plans supported

- **Max Plan** (Claude) — tracks messages and tokens per 5-hour rolling window + weekly cap
- **API Plan** — tracks dollars per day/week/month (Anthropic, OpenAI)
- **Pro / Team** — configurable

### Providers supported

- **Claude Code** (`~/.claude/projects/`)
- **OpenAI Codex CLI** (`~/.codex/sessions/`)
- **Generic JSONL** — any tool with usage-logging session files
- **More coming** — Cursor, Copilot, Devin (contributions welcome)

---

## Quick Start

Requires [Bun](https://bun.sh/) or Node 22+. See [Install in 3 steps](#install-in-3-steps) above.

### Configure your plan

Edit `~/.aegis/config.json`:

```json
{
  "plan": "max_5x",
  "budget": {
    "messages_per_5h": 225,
    "tokens_per_5h": 50000000,
    "weekly_messages": 3150,
    "daily_limit_usd": 100
  },
  "enforcement": {
    "mode": "alert"
  }
}
```

**`enforcement.mode: "alert"` is the safe default** — AEGIS warns loudly but never kills your processes automatically. Change to `"enforce"` only when you trust the behavior.

### Start the services

```bash
# Start monitor (watches session files)
aegis-monitor &

# Start dashboard
aegis-dashboard &

# Open http://localhost:4850
```

### Check status anytime

```bash
aegis status
```

```
  AEGIS — Max Plan (max_5x)
  ────────────────────────────────────────────────────────────

  5h window:   [======........................] 21%
    Messages:  41 / 225
    Tokens:    5.7M / 50.0M
    Resets in: 4h 41m

  Weekly:      [..............................] 1%
    Messages:  25 / 3150
    Tokens:    5.7M / 700.0M
```

---

## Commands

| Command | Purpose |
|---------|---------|
| `aegis init` | Set up config + database |
| `aegis status` | Current budget + active sessions + recent alerts |
| `aegis budget show` | Show configured limits |
| `aegis budget set <field> <value>` | Update budget (e.g. `aegis budget set daily 50`) |
| `aegis kill` | SIGKILL all agent processes |
| `aegis kill --stop` | SIGSTOP (pause, resumable) |
| `aegis resume` | SIGCONT paused processes |
| `aegis pause` | Same as `kill --stop` |
| `aegis check-budget` | Hook: exit 0 = allow, exit 2 = block (used by Claude Code hooks) |
| `aegis check-spawn` | Hook: agent spawn limit + HanumanG delegation check |
| `aegis check-shield` | Hook: LakshmanRekha injection/credential/exfil detection |
| `aegis register --id <id>` | Check-in: create policy, register agent in state machine |
| `aegis close --id <id>` | Check-out: mark COMPLETED, rebalance parent budget pool |
| `aegis resume <agent-id>` | Display resume manifest for a force-closed agent |
| `aegis cost [session-id]` | Cost attribution tree — per-agent spend + overspend risk |
| `aegis quarantine list` | List all QUARANTINED/ORPHAN agents |
| `aegis quarantine release <id>` | Human-in-the-loop release (requires --reason) |
| `aegis valve list` | List all gate valve records |
| `aegis valve status <id>` | Show perm_mask, class_mask for an agent |

---

## Claude Code Integration

### 1. Inline status line (see AEGIS inside Claude Code)

Add to `~/.claude/settings.json`:

```json
{
  "statusLine": {
    "type": "command",
    "command": "aegis statusline"
  }
}
```

You'll see a live one-line status at the bottom of Claude Code:

```
◉ AEGIS 126/225msg 56% reset:4h27m
```

- Green under 70%, yellow 70-90%, red above 90%
- Updates automatically as the status line refreshes
- Works for Max Plan (msgs/tokens) and API plan ($)

### 2. Budget enforcement (block tool calls over budget)

Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "",
      "hooks": [{
        "type": "command",
        "command": "bash ~/.aegis/pre-tool-use.sh"
      }]
    }]
  }
}
```

The hook runs before every tool call:
- Budget gate → `aegis check-budget` (warns at 80%, blocks at 100%)
- Agent spawn → `aegis check-spawn` (HanumanG delegation check, loop detection, depth limit)
- Shell commands → `aegis check-destructive` (the KAVACH gate, below)
- All other tools → `aegis check-shield` (LakshmanRekha injection, credential, exfil detection)

#### The budget and spawn hooks

`aegis check-budget` runs before every tool call and `aegis check-spawn` before an agent is spawned. Both learn which session is calling from the `session_id` in the hook's payload.

| | Default mode (`alert`) | `enforcement.mode: "enforce"` |
|---|---|---|
| The day's or the week's budget is spent | a warning | stopped |
| This session's agent is at 80% of its own cap | a warning | a warning |
| … at 95% | a warning | stopped, and the agent is told to stop |
| The session is at its spawn limit, or too little of the day's budget is left | a warning | stopped |
| A spawn with no description or no real prompt | a warning | stopped |
| A spawn from a session the hook cannot identify | a warning | stopped |
| An agent that has been told to stop | stopped | stopped |

**What they do not do.**

- **In the default mode they stop almost nothing.** The warnings are the product until you choose `enforce`.
- **They fail open.** If the hook's own database cannot be read, the call goes ahead; the hook says so on stderr. If `config.json` cannot be read, the defaults are used, which means `alert`; the hook says that too.
- **The hook does not count spawns or spend.** The monitor (`aegis-monitor`) does, from the session's transcript. With no monitor running, the limits never move.
- **A limit of 0 means no limit**, and a mode spelled any other way than `enforce` is `alert`.
- **The permission-mask check on spawning (Level 0) is off unless `kavach.perm_mask_levels` is `"live"`**, the same switch the destructive gate uses.
- **A hook script written before 2.6.0 does not pass the payload to `check-budget`.** Add `printf '%s' "$INPUT" |` in front of it, or remove the script and run `aegis init` again.

#### The destructive-command gate

`aegis check-destructive` reads a shell command before it runs and exits 0 (go ahead) or 2 (stop). `aegis init` installs its rules at `~/.aegis/destructive-rules.json` and wires it into the hook script. (A hook script written by an earlier version does not call it; add the line, or remove the script and run `aegis init` again.)

It stops, among others: dropping a database, table, schema or column; truncating a table; deleting rows; `dropdb`; a Prisma reset or push; removing Docker volumes; stopping PostgreSQL; removing its data directories; `chmod 777`; and a recursive removal of the root or the home directory however the flags are written. The full list is the rules file. A command that only shows such words (`echo`, `grep`, a commit or tag message, comment lines alone) is let through and says so.

**Approving a refused command.** Nothing typed into a command overrides the gate. When it refuses, it prints a code. A person, in their own terminal, runs:

```bash
aegis approve-destructive            # list what was refused
aegis approve-destructive <code>     # approve that one command
```

The same command, run again unchanged within ten minutes, then goes through once. The use is recorded. A different command, or a second run, is refused again. The shield stops `approve-destructive` when it arrives as a tool call.

To have the gate ask a person over a channel outside the machine and wait for the answer, set `kavach.destructive_critical` to `"approve"` in `~/.aegis/config.json`.

**What it does not do.**

- **It reads the text of the command.** A statement inside a file the command names, a target held in a variable, a target that arrives through `xargs`: not seen.
- **The list is a list.** Removing a system directory other than the root or home, wiping a disk, a forced push, an update with no filter: not on it.
- **It over-stops in places.** A search for a destructive phrase that is piped onward is refused; so is a here-document whose text contains one.
- **The approval is a file under the same user the agent runs as.** The shield stops a tool call from writing it or running the approve command, but code an agent runs through an interpreter of its own could write it. It is a deliberate, recorded act that an agent has to go out of its way to forge, not a boundary the operating system enforces. The outside-channel approval above is the stronger form.
- **With no rules file it refuses every shell command.** A gate that cannot read its rules does not guess.

#### What the shield stops, and what it does not

`aegis check-shield` reads the JSON the harness sends before a tool call and exits 0 (go ahead) or 2 (stop).

| It stops, in the default configuration | How |
|---|---|
| A read of a credential file — `.env` and its variants, ssh private keys, anything in `~/.ssh` `~/.gnupg` `~/.aws` that is not public, `credentials.json`, `.netrc`, `.npmrc`, data files in a `secrets/` folder | by the Read tool, **or named in a shell command that would show or copy its content** (`cat`, `grep`, `cp`, `tar`, `scp`, `curl -F @…`, `< file`) |
| A write to a persistence target — shell start-up files, cron, systemd units, `authorized_keys`, `ld.so.preload` | by Write / Edit / MultiEdit / NotebookEdit, **or by a shell redirect, `tee`, `cp`, `mv`, `ln`, `sed -i`, `dd`, `curl -o`, `crontab`** |
| A write to the shield's own files — everything in `~/.aegis/`, and `~/.claude/settings.json` / `settings.local.json` | the same ways, plus `rm`, `chmod`, `truncate`. **No rules file switches this off.** |
| Known instruction-override phrases in text a tool returns | a list of patterns, matched after folding full-width letters and removing invisible characters |

Paths are resolved first (`~`, relative paths, `/./`, `/../`, symlinks) and matched on whole segments: `.env.example`, `docs/secrets-management.md` and `docs/.bashrc-explained.md` are not stopped. Ordinary uses are let through: `ssh -i key`, `ssh-add`, `source .env`, `docker compose --env-file .env`, `cp .env.example .env`, `chmod 600`.

In `enforcement.mode: "enforce"` it also stops an upload or fetch that names a paste, file-drop or request-catcher site, and a network tool run within a few calls of a credential read or a large read. The network tool is the program that runs, wherever it stands in the command (`/usr/bin/curl`, `;curl`, `sudo curl`, `bash -c "curl …"`, `$(curl …)`). **In the default mode, `alert`, these are warned about and allowed.**

**What it does not do.** The first three, and the idiom, are pinned by tests in `src/shield/hardening.test.ts`, so they cannot change unnoticed.

- **It reads the text of a call; it does not run a shell.** A path or program held in a variable, built at run time (`$(echo curl)`, the shell's field-separator variable used in place of spaces, base64 piped to `bash`), expanded by a glob (`cat .en*`), or inside a script file or an interpreter's own code (`python3 -c "open(…)"`) is not seen.
- **The lists are lists.** A network tool that is not listed (`scp`, `rsync`), a sink that is not listed, a bare IP address, a persistence path that is not listed: not stopped.
- **Phrases are wording.** A reworded instruction, look-alike letters from another alphabet, spaced-out letters, another language: not matched.
- **It fails open.** Input that is not JSON, an error inside the shield, or the harness giving up on a slow hook: the call goes ahead. The first two say so on stderr.
- **It sees a tool's reply only if you wire it to `PostToolUse` as well**, and by then the tool has run: the verdict can only tell the agent to distrust what came back. The output of a shell command is not read as a reply.
- **One common idiom is stopped:** `export $(cat .env | xargs)`. Use `set -a; source .env; set +a`.
- **It knows Claude Code's tool names** (`Bash`, `Read`, `Write`, `Edit`, `MultiEdit`, `NotebookEdit`, `WebFetch`). Another harness's names are not recognised.

The shield is a net for the plain cases, which are the common ones. It is not a sandbox, and passing it is not proof that a call is safe. The kernel layer ([`@xshieldai/agent-kernel`](https://www.npmjs.com/package/@xshieldai/agent-kernel)) is the one that does not depend on the text of a command.

To make an exemption, a person edits `~/.aegis/shield-rules.json` (lists: `credential_paths`, `persistence_targets`, `exfil_commands`, `drop_sites`, `injection_patterns`). A path rule is whole segments; end it with `/` for a folder and everything under it.

`aegis init` generates the hook script automatically at `~/.aegis/pre-tool-use.sh`.

Hook latency: about 150 ms per call on a small server (Bun start + SQLite read), measured 2026-10-05.

### 3. Dashboard (your own, local-first)

Every install is **local-first**. Your dashboard runs on YOUR machine:

```
http://localhost:4850
```

Not shared with anyone. Your SQLite DB, your config, your data. If you want to expose it publicly (e.g. via a reverse proxy on your own domain), see the [Dashboard](#dashboard) section below.

---

## OpenAI Codex Integration

AEGIS auto-detects Codex session files at `~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl` and parses the `token_count` event format.

No setup required — just run both tools and AEGIS tracks both:

```bash
# Terminal 1
claude

# Terminal 2
codex exec "your task"

# AEGIS sees both in one dashboard
aegis status
```

Codex sessions appear with `codex-` prefix in the sessions list.

---

## Dashboard

The full dashboard ships in this repo and runs locally. Start it with:

```bash
aegis-dashboard &
# → http://localhost:4850
```

**What's in the dashboard:**

| Panel | Description |
|---|---|
| Budget / Usage | 5-hour window, weekly cap, daily/monthly spend — live bars |
| Live Intelligence | Active processes, token velocity, projected burn rate |
| Agent Processes | Per-PID view with CPU/mem, PAUSE/KILL per process |
| 7-Day Trend | Spend sparklines |
| Controls | PAUSE ALL · KILL ALL · RESUME · Enforce Mode toggle |
| Active Sessions | Per-session cost, message count, agent spawns |
| **KAVACH Approvals** | Pending approvals with STOP / ALLOW / EXPLAIN buttons |
| Alerts | Budget warnings, anomalies, spawn limit events |

**KAVACH panel** — when an agent tries a destructive command, the approval appears here in real time. You can decide from the dashboard or reply to the Telegram/WhatsApp notification. The panel shows:
- Command, blast radius consequence, level (L1–L4)
- Time remaining before default-safe timeout (silence = STOP)
- For L4 dual-control: `🔐 AWAITING 2ND APPROVAL` badge with first approver identity

Default port: `4850`. Configurable in `config.json`.

### Public hosting

Reverse-proxy through nginx/Caddy/Cloudflare. Example nginx config:

```nginx
server {
    listen 443 ssl http2;
    server_name aegis.yourdomain.com;
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:4850;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        # SSE support
        proxy_buffering off;
        proxy_read_timeout 3600s;
        proxy_set_header Upgrade $http_upgrade;
    }
}
```

---

## Configuration Reference

`~/.aegis/config.json`:

```json
{
  "plan": "max_5x",
  "budget": {
    "daily_limit_usd": 100,
    "weekly_limit_usd": 400,
    "monthly_limit_usd": 1200,
    "session_limit_usd": 25,
    "messages_per_5h": 225,
    "tokens_per_5h": 50000000,
    "weekly_messages": 3150,
    "weekly_tokens": 700000000,
    "spawn_limit_per_session": 50,
    "spawn_concurrent_max": 20,
    "cost_estimate_threshold_usd": 10
  },
  "heartbeat": {
    "timeout_seconds": 300,
    "action": "alert"
  },
  "dashboard": {
    "port": 4850
  },
  "monitor": {
    "health_port": 4851,
    "watch_paths": [
      "~/.claude/projects",
      "~/.codex/sessions"
    ],
    "poll_interval_ms": 2000
  },
  "alerts": {
    "terminal_bell": true,
    "webhook_url": null
  },
  "enforcement": {
    "mode": "alert",
    "excluded_pids": [],
    "excluded_ppids": []
  }
}
```

### Plan presets (approximate)

Anthropic doesn't publish exact Max Plan limits. These are conservative estimates:

| Plan | Messages / 5h | Tokens / 5h | Weekly Messages |
|------|---------------|-------------|-----------------|
| `max_5x` | 225 | 50M | 3,150 |
| `max_20x` | 900 | 200M | 12,600 |
| `pro` | 45 | 10M | 630 |
| `api` | — | — | — (uses USD) |

Calibrate to your actual usage — these are starting points.

---

## Safety

**AEGIS defaults to alert-only mode.** It warns loudly but never auto-kills your processes.

To enable automatic enforcement:
```json
{ "enforcement": { "mode": "enforce" } }
```

Even in enforce mode, AEGIS excludes:
- Its own PID and parent PID
- Any PIDs you add to `excluded_pids`
- Any processes whose parent is in `excluded_ppids`

This prevents the "own-goal" problem where AEGIS kills its own user's active session.

---

## Architecture

```
┌──────────────────────────────────────────────────┐
│  Dashboard (4850)     Monitor (4851)              │
│  Fastify + SSE        JSONL watcher + enforcer    │
└─────────────┬─────────────┬────────────────────┘
              │             │
              └──────┬──────┘
                     │
              ┌──────▼──────┐
              │  SQLite DB   │  (~/.aegis/aegis.db)
              │  usage_log   │
              │  sessions    │
              │  budget_state│
              │  alerts      │
              └──────┬──────┘
                     │
        ┌────────────┴────────────┐
        │                         │
  ┌─────▼──────┐          ┌──────▼───────┐
  │ Claude Code│          │  OpenAI Codex │
  │ session    │          │  rollout      │
  │ JSONL      │          │  JSONL        │
  └────────────┘          └───────────────┘
```

### Components

- **Monitor daemon** (`aegis-monitor`) — watches JSONL files, parses usage, enforces budgets
- **Dashboard** (`aegis-dashboard`) — Fastify server + SSE + static HTML
- **CLI** (`aegis`) — status, kill-switch, budget config, hook integration
- **Hook script** (`~/.aegis/pre-tool-use.sh`) — Claude Code PreToolUse integration

---

## Testing — AEGIS on AEGIS

AEGIS validates its own governance engine by running as a **real registered agent** inside itself. The test runner registers in the production `~/.aegis/aegis.db`, executes all 10 scenario probes (each against an isolated HOME directory), then closes itself as `FORCE_CLOSED` (clean) or `FAILED`.

```bash
bun src/test-agents/runner.ts           # run all 10 scenarios
bun src/test-agents/runner.ts 04 09    # run specific scenarios
```

| # | Scenario | What it proves |
|---|----------|----------------|
| 01 | Budget Overflow | `check-budget` exits 2 when daily cap exceeded; exits 0 in alert mode |
| 02 | KAVACH DAN Classify | `classifyCommand()` returns correct L1–L4 level; HIGH rule exits 2 immediately |
| 03 | Injection Block | `check-shield` quarantines "ignore all previous instructions" prompt injection |
| 04 | Spawn Depth Limit | Agent at `max_depth` cannot spawn children — exit 2 with "depth" in stderr |
| 05 | L1 Soft Stop | Agent with `stop_requested=1` is blocked by `check-shield` |
| 06 | Budget Inheritance | Child budget capped by parent's remaining pool; over-allocation rejected |
| 07 | Zombie State | Watchdog transitions stale agent (>5 min heartbeat gap) to ZOMBIE |
| 08 | Orphan Detection | FORCE_CLOSED parent → RUNNING child transitions to ORPHAN (INF-KAV-007) |
| 09 | Credential Read Block | Read of `~/.ssh/id_rsa` → `check-shield` exits 2 (LakshmanRekha credential path) |
| 10 | Loop Count Quarantine | `loop_count > 50` → `check-spawn` quarantines agent (INF-KAV-014) |

Each test scenario is fully isolated: it creates its own `HOME=/tmp/aegis-test-{name}`, its own SQLite DB, its own config, and cleans up after itself. No test can contaminate another or the production database.

This pattern — governance infrastructure testing itself under its own governance — is described in: [DOI 10.5281/zenodo.19625473](https://doi.org/10.5281/zenodo.19625473)

---

## Why This Matters

This is an **early signal** of a structural shift: we're moving from SaaS to Agent-as-a-Service (AaaS).

- **SaaS:** user clicks, one action = one action, cost predictable
- **AaaS:** user instructs, one action = N agent spawns, cost unbounded

The infrastructure for governing this new execution model does not exist yet. AEGIS is one piece of that infrastructure.

Read the incident that spawned this project: [`docs/incident.md`](docs/incident.md)

---

## On the category — Fin Operator and the case for open primitives

On **15 May 2026**, Intercom (since renamed to **Fin**) launched [Fin Operator](https://www.fin.ai/), a Pro-tier subscription product whose **"proposal system"** puts a human approval gate between an AI agent and the systems it changes. Every modification appears as a diff. Nothing goes live without a click.

If you've read this far, you'll recognise the pattern — it is structurally the same as the KAVACH DAN Gate above. A pull-request-shaped intercept between agent intent and irreversible action.

AEGIS was born from a real $200 incident on **17 April 2026**, about a month before Fin Operator's launch. The 7-axis HanumanG spawn check, the PRAMANA attestation chain, and the human-approval default-deny gate are the same architectural primitives that a $400M-ARR vendor has now validated as the category answer to agentic governance.

| | Fin Operator (2026-05-15) | AEGIS (2026-04-17) |
|---|---|---|
| Distribution | Pro-tier subscription, vendor-hosted | `npm install @xshieldai/aegis`, self-hosted |
| License | Proprietary | AGPL-3.0 (kernel) + BSL-1.1 → AGPL-3.0 in 4 years (EE) |
| Scope | Bound to the Fin platform | Vendor-neutral (Claude Code, OpenAI Codex, Cursor, custom) |
| Self-host | No | Yes — local-first by default |
| Audit | Trust the vendor | `grep -rn "fetch(" src/` |
| Pricing | Pro tier + usage blocks | $0 OSS · BSL-1.1 EE free up to 3 concurrent sessions |

AEGIS does not compete with Fin Operator on customer-service workflows — that is a different product surface and not the contest. AEGIS competes with the *idea* that agent governance has to be a subscription you cannot read the source of.

The category becoming legitimate is welcome news. The primitive being open is the part worth choosing.

---

## AGPL3 Core vs Enterprise Edition (EE)

KavachOS ships in two tiers. The kernel enforcement layer — the part that actually stops syscalls — is **open source**. You can audit what runs next to your production agents.

> **Kernel enforcement (seccomp-bpf + Falco integration) is AGPL-3.0. You can audit what runs next to your production agents.**

| Capability | Layer | License | Install |
|---|---|---|---|
| Budget governor (daily/session/agent) | KAVACH orchestrator | **AGPL-3.0** | `@xshieldai/aegis` |
| DAN gate — WhatsApp / Telegram human-in-loop | KAVACH orchestrator | **AGPL-3.0** | `@xshieldai/aegis` |
| `perm_mask` / `class_mask` bitmask policy | KAVACH orchestrator | **AGPL-3.0** | `@xshieldai/aegis` |
| Gate valve (throttle → crack → close) | KAVACH orchestrator | **AGPL-3.0** | `@xshieldai/aegis` |
| HTTP Gate API (`/api/v1/kavach/gate`) | KAVACH orchestrator | **AGPL-3.0** | `@xshieldai/aegis` |
| n8n community nodes (4 nodes) | KAVACH adapters | **AGPL-3.0** | `@xshieldai/n8n-nodes` |
| LangChain callback adapter | KAVACH adapters | **AGPL-3.0** | `xshieldai-langchain` |
| CA-006 LLM injection detection | KAVACH-POSTURE | **AGPL-3.0** | `@xshieldai/aegis` |
| Basic HanumanG (7 delegation axes) | KAVACH-POSTURE | **AGPL-3.0** | `@xshieldai/aegis` |
| seccomp-bpf profile generator | KAVACH-KERNEL | **AGPL-3.0** | `@xshieldai/aegis` |
| Falco rule generator + event watcher | KAVACH-KERNEL | **AGPL-3.0** | `@xshieldai/aegis` |
| SCMP_ACT_NOTIFY supervisor (no-restart expansion) | KAVACH-KERNEL | **AGPL-3.0** | `@xshieldai/aegis` |
| KavachOS CLI (`kavachos run/audit/generate/rules`) | KAVACH-KERNEL | **AGPL-3.0** | `@xshieldai/aegis` |
| PRAMANA Merkle receipt chain + S3 anchoring | KAVACH orchestrator | **BSL-1.1 → AGPL-3.0\*** | contact [captain@ankr.in](mailto:captain@ankr.in) |
| HanumanG EE — posture registry + report cards | KAVACH-POSTURE | **BSL-1.1 → AGPL-3.0\*** | contact [captain@ankr.in](mailto:captain@ankr.in) |
| Dual-control L4 approval (two approvers) | KAVACH orchestrator | **BSL-1.1 → AGPL-3.0\*** | contact [captain@ankr.in](mailto:captain@ankr.in) |
| Slack notification channel | KAVACH orchestrator | **BSL-1.1 → AGPL-3.0\*** | contact [captain@ankr.in](mailto:captain@ankr.in) |
| Maritime injection signatures (AIS/NMEA/Modbus) | KAVACH-POSTURE | **BSL-1.1 → AGPL-3.0\*** | contact [captain@ankr.in](mailto:captain@ankr.in) |
| Multi-tenant session isolation | KAVACH orchestrator | **BSL-1.1 → AGPL-3.0\*** | contact [captain@ankr.in](mailto:captain@ankr.in) |
| Kubernetes sidecar + admission webhook | KAVACH infra | **BSL-1.1 → AGPL-3.0\*** | Phase 6 build |
| EU AI Act evidence package | KAVACH compliance | **BSL-1.1 → AGPL-3.0\*** | Phase 5 build |

\* BSL-1.1 converts to AGPL-3.0 after 4 years. EE is distributed via private GitHub repo to design partners — not on npm. Contact [captain@ankr.in](mailto:captain@ankr.in).

### Activate EE

```bash
# EE distributed via private repo — not npm
# Clone: git clone git@github.com:rocketlang/kavachos-ee.git  (design partner access)
export AEGIS_EE_LICENSE_KEY=your_signed_key
aegis status   # EE: active
```

---

## What's new in v2.2.0 (2026-05-17) — Agentic Control Center

The dashboard at port 4850 now includes a consolidated cockpit page that
renders events from every `@xshieldai/*` primitive in one view.

**New routes** (all gated by the same session auth as existing dashboard
routes — opt-in via `dashboard.auth.enabled: true` in `~/.aegis/config.json`,
which is the default after `aegis init`):

- **`/control-center`** — single-page cockpit with 6 primitive zones
  + AOS-shaped strip (Boot Sequence · Primitive Process List · About this AEGIS)
  + PRAMANA OSS panel (renders existing `src/kernel/merkle-ledger.ts`)
  + EE-aware PRAMANA extra panel (renders only when `@xshieldai/agent-kernel-ee` is installed)
- **`/agent/:id`** — per-agent timeline across all primitives, ordered by emission time
- **`/suite`** — `@xshieldai/*` package inventory (from consumer's `node_modules`)
- **`/api/acc/health`** — JSON event counts by primitive
- **`/api/acc/events`** — JSON event query (by primitive or agent_id)
- **`/api/acc/events/stream`** — SSE stream of new events (1.5s polling)
- **`/api/suite/inventory`** — JSON inventory

**To populate the cockpit**, install the meta-package + call `wireAllToBus()`:

```bash
npm install @xshieldai/aegis-suite
```

```typescript
import { wireAllToBus } from '@xshieldai/aegis-suite';
wireAllToBus();
// → every @xshieldai/* primitive event now records to ~/.aegis/acc-events.db
// → visit http://localhost:4850/control-center
```

Same release wave shipped these v0.2.0 primitive packages with opt-in
`setEventBus()` API:
[`@xshieldai/aegis-guard`](https://www.npmjs.com/package/@xshieldai/aegis-guard)
· [`@xshieldai/chitta-detect`](https://www.npmjs.com/package/@xshieldai/chitta-detect)
· [`@xshieldai/lakshmanrekha`](https://www.npmjs.com/package/@xshieldai/lakshmanrekha)
· [`@xshieldai/hanumang-mandate`](https://www.npmjs.com/package/@xshieldai/hanumang-mandate)
· [`@xshieldai/aegis-suite`](https://www.npmjs.com/package/@xshieldai/aegis-suite) v0.2.0 with `wireAllToBus()`.

**Phase-1 limits** (v2.2.0):
- SSE polling at 1.5s interval (not push-based) — fine for most cockpits, finer-grained push deferred to v2.3+
- WAL cross-process visibility — if consumer + dashboard are in different processes, call `handle.checkpoint()` after batches OR rely on auto-checkpoint at ~1000 writes
- PRAMANA EE panel detected via runtime `require.resolve('@xshieldai/agent-kernel-ee')` — invisible if EE not installed
- Filter UI on `/agent/:id` deferred to v2.3 (timeline works without it)
- Consumer needs `@xshieldai/aegis-suite` v0.2.0+ for `wireAllToBus()` — direct `setEventBus()` per-primitive also works

See [DAILY-LOG.md](DAILY-LOG.md) for the 5-day build chronology.

---

## Roadmap

- [x] Phase 0 — Monitor + CLI + Dashboard + Max Plan + Codex support
- [x] Phase 1 — KAVACH-KERNEL: seccomp-bpf + Falco + SCMP_ACT_NOTIFY supervisor (v2.0.0)
- [x] Phase 1A — Framework adapters: n8n (4 nodes) + LangChain callback (v2.0.0)
- [x] Phase 2 — PRAMANA Merkle ledger + S3 anchoring (in OSS since v2.1.0 — corrected from earlier EE misclassification per OPEN-CORE-BOUNDARY.md v0.5)
- [x] Phase 2a — **Agentic Control Center (v2.2.0)** — cockpit page + per-agent timeline + SSE + AOS-shaped polish
- [ ] Phase 3 — L7 transparent proxy (TLS-terminating, zero agent code change)
- [ ] Phase 4 — SPIFFE/mudrika identity (agent SVID, 55-min auto-rotate)
- [ ] Phase 5 — EU AI Act evidence package (Aug 2, 2026 deadline)
- [ ] Phase 6 — Kubernetes sidecar + DaemonSet (EE enterprise path)

---

## Contributing

Issues and PRs welcome at [github.com/rocketlang/aegis](https://github.com/rocketlang/aegis).

Especially wanted:
- Parsers for new providers (Cursor, Copilot, Devin, Windsurf, custom agents)
- Plan presets calibrated against real bills
- Anomaly detection heuristics
- Dashboard improvements
- Documentation in other languages

---

## License

[AGPL-3.0](LICENSE) © Capt. Anil Sharma

OSS under AGPL-3.0 — copyleft applies to network deployments. Commercial license (SaaS, enterprise) available via [captain@ankr.in](mailto:captain@ankr.in).

---

## Credits

Built from pain. The incident report behind AEGIS: [docs/incident.md](docs/incident.md)

> "Autonomy without control = financial risk."
