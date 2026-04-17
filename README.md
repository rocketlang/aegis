# AEGIS

> The kill-switch between your AI agents and your credit card.

[![npm version](https://img.shields.io/npm/v/@rocketlang/aegis.svg)](https://www.npmjs.com/package/@rocketlang/aegis)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.19625473.svg)](https://doi.org/10.5281/zenodo.19625473)

**AEGIS** — Agentic Execution Governance & Intelligence System. A vendor-neutral governance layer for agentic AI tools like Claude Code, OpenAI Codex, Cursor, and any framework that writes session logs or makes API calls.

Born from a real $200 incident: a user stopped using Claude Code, walked away, came back to find weekly Max Plan usage fully exhausted with no visibility into what executed.

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

### Five capabilities

| # | Capability | What it does |
|---|------------|--------------|
| 1 | **Unified Usage Dashboard** | All surfaces, all sessions, all spend — one real-time view |
| 2 | **Hard Budget Caps** | Per session, per 5h window, per day/week — tiered warnings at 80%/90%/100% |
| 3 | **Kill-Switch** | `aegis kill` sends SIGKILL/SIGSTOP to all agent processes in under 1 second |
| 4 | **Agent Spawn Governance** | Block subagent spawns above a configurable limit per session |
| 5 | **Anomaly Detection** | Alert on spend spikes, night-time activity, runaway sessions |

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

### Install

```bash
npm install -g @rocketlang/aegis
```

Requires [Bun](https://bun.sh/) or Node 22+.

### Initialize

```bash
aegis init
```

Creates `~/.aegis/` with default config and SQLite database.

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
| `aegis check-spawn` | Hook: check agent spawn limit |

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
- Normal tool calls → `aegis check-budget` (exit 2 blocks if over budget)
- `Agent` tool → `aegis check-spawn` (exit 2 blocks if over spawn limit)

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

![AEGIS Dashboard](https://via.placeholder.com/800x500?text=AEGIS+Dashboard)

- **5-hour window** card with messages + tokens + reset countdown
- **Weekly cap** card
- **Active sessions** list (unified across providers)
- **Alerts feed** — budget warnings, anomalies, spawn limits
- **Action buttons** — PAUSE ALL, KILL ALL, RESUME
- **Real-time updates** via Server-Sent Events
- **Plan badge** shows your configured tier

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

MIT © Capt. Anil Sharma / ANKR Labs

---

## Credits

Built from pain. The incident report behind AEGIS: [docs/incident.md](docs/incident.md)

> "Autonomy without control = financial risk."
