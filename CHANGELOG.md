# Changelog

All notable changes to AEGIS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] — 2026-04-17

### Added
- Initial release
- Monitor daemon that watches Claude Code (`~/.claude/projects/`) and OpenAI Codex (`~/.codex/sessions/`) session logs
- CLI with `status`, `budget`, `kill`, `pause`, `resume`, `check-budget`, `check-spawn`, `init` commands
- Fastify-based dashboard at http://localhost:4850 with SSE real-time updates
- SQLite persistence (`~/.aegis/aegis.db`)
- Tiered warnings at 80% / 90% / 100% budget
- Max Plan mode (tracks messages + tokens per 5-hour rolling window)
- API Plan mode (tracks dollars per day/week/month)
- Alert-only default (does not auto-kill processes)
- PID exclusion list to prevent killing AEGIS itself or user's active session
- Claude Code `PreToolUse` hook integration for pre-flight budget enforcement
- Vendor-neutral JSONL parser (supports Claude Code + Codex + generic formats)
- Agent spawn governance (blocks Agent tool above configured limit)
- Anomaly detection (alerts on 5x spend rate spikes)

### Known limitations
- Cannot see claude.ai web usage (no public Anthropic API)
- Token-to-USD conversion for Max Plan is approximate (Anthropic doesn't publish exact pricing)
- Mobile device sessions (Termux) only visible if running on the same machine
- Heartbeat detection stub (does not yet auto-pause on user absence)
