# AEGIS

> **Stops your AI agent from destroying your database without asking.**

[![npm version](https://img.shields.io/npm/v/@rocketlang/aegis.svg)](https://www.npmjs.com/package/@rocketlang/aegis)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.19625473.svg)](https://doi.org/10.5281/zenodo.19625473)
[![Security](https://img.shields.io/badge/trust-audit%20us-green)](SECURITY.md)

**AEGIS** (Agentic Execution Governance & Intelligence System) is a vendor-neutral kill-switch for AI agents. Works with Claude Code, OpenAI Codex, Cursor, and any tool that writes session logs or makes API calls.

Born from a real $200 incident: a user stopped using Claude Code, walked away, came back to find their weekly Max Plan fully exhausted with no visibility into what ran.

---

## Install in 3 steps

```bash
# 1. Install
npm install -g @rocketlang/aegis

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
| 1 | **KAVACH Gate** | PreToolUse hook intercepts destructive commands before execution — human approves via Telegram/WhatsApp or dashboard |
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
- All other tools → `aegis check-shield` (LakshmanRekha injection, credential, exfil detection)

`aegis init` generates the hook script automatically at `~/.aegis/pre-tool-use.sh`.

Hook latency: ~30-50ms (Bun cold start + SQLite read).

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

## Why This Matters

This is an **early signal** of a structural shift: we're moving from SaaS to Agent-as-a-Service (AaaS).

- **SaaS:** user clicks, one action = one action, cost predictable
- **AaaS:** user instructs, one action = N agent spawns, cost unbounded

The infrastructure for governing this new execution model does not exist yet. AEGIS is one piece of that infrastructure.

Read the incident that spawned this project: [`docs/incident.md`](docs/incident.md)

---

## Roadmap

- [x] Phase 0 — Monitor + CLI + Dashboard + Max Plan + Codex support
- [ ] Phase 1 — Heartbeat detection (pause when user walks away)
- [ ] Phase 2 — Proxy mode (intercept API calls pre-flight)
- [ ] Phase 3 — Multi-device sync
- [ ] Phase 4 — Agent Budget Attestation (ABA) protocol spec
- [ ] Phase 5 — Integrations: Cursor, Copilot, Devin, Windsurf
- [ ] Phase 6 — Team/enterprise mode with per-user attribution

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
