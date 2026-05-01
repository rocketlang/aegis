# Changelog

All notable changes to AEGIS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [2.0.0] — 2026-04-30

### Added (KAVACH-KERNEL — Phase 1, AGPL-3.0)
- **seccomp-bpf profile generator** — `trust_mask` + domain → libseccomp JSON profile; `src/kernel/seccomp-profile-generator.ts`
- **Falco 0.43.1 integration** — `falco-rule-generator.ts` (maritime/freight/general rules) + `falco-watcher.ts` (stdout → PRAMANA receipts + gate-valve escalation)
- **SCMP_ACT_NOTIFY supervisor** — kernel pauses blocked syscall → Telegram ALLOW/STOP → transparent resume or EPERM; `apply-seccomp.py` fork architecture
- **Cgroup BPF egress skeleton** — domain egress allowlist types wired; BPF program in Phase 1E
- **KavachOS CLI** — `kavachos run/generate/profile/audit/rules/init/version` — published `@rocketlang/kavachos@2.0.0`
- **Profile versioning** — SHA-256 hash + `profile_store.ts` in `aegis.db`; drift detection on session start

### Added (Framework Adapters — Phase 6A)
- **HTTP Gate API** — `POST /api/v1/kavach/gate`, `GET /api/v1/kavach/health`, `GET /api/v1/kavach/state`, `GET /api/v1/kavach/audit` — all unauthenticated for adapter-safe access
- **`@rocketlang/n8n-nodes-kavachos@1.1.0`** — 4 community nodes: KavachGate, KavachRun, KavachBudget, KavachAudit; `AegisApi` credential
- **`langchain-kavachos@1.0.0`** — `KavachGateCallback` (duck-typed, `on_tool_start` intercept); `AegisClient` stdlib-only; `KavachGateError` typed exception; zero mandatory deps

### Added (AGPL3/EE Split — Phase 8)
- **`ee/` directory** — BSL-1.1 EE modules: PRAMANA receipts, HanumanG EE, dual-control, Slack notifier, maritime signatures, multi-tenant
- **`ee/license.ts`** — `isEE()` reads `AEGIS_EE_LICENSE_KEY` env var; graceful degradation when absent
- **`@rocketlang/kavachos-ee@1.0.0`** — EE package with BSL-1.1 (converts to AGPL-3.0 after 4 years)
- **EE status** in `aegis status` output and dashboard health badge

### Changed
- Package description updated to reflect KavachOS scope
- README updated with AGPL3/EE two-layer table and roadmap

---

## [0.2.0] — 2026-04-29

### Added
- **`aegis init` auto-patch**: automatically wires `PreToolUse` hook and `statusLine` into `~/.claude/settings.json` on first run — no manual JSON editing required.
- **Bitmask-native context** (Phase 1c): `perm_mask`, `class_mask`, `violation_mask` as integers on every agent record. Bit-check O(1) gate runs before string-match enforcers.
- **Gate valve**: `narrowMask()` progressively clears permission bits on violations without quarantine. `aegis restore-mask` for human restoration.
- **KAVACH DAN gate** (Phase 1b/1c): Telegram/WhatsApp approval flow for dangerous actions (L1–L4). Dual-control for L4.
- **Forja protocol**: STATE, TRUST, SENSE, PROOF endpoints at `/api/v2/forja/` — 100% rule annotation coverage.
- **Agent policy schema docs**: `docs/agent-policy-schema.md` — full schema reference for `aegis-agent-policy-v1`.
- **Three example policies**: `examples/agents/example-worker.json`, `example-compliance-auditor.json`, `example-unknown-agent.json`.
- **`aegis cost`**: cost attribution tree with parent/child nesting and risk flags.
- **`aegis mask-log <id>`**: gate valve history per agent.
- **`aegis restore-mask <id>`**: human-only perm_mask restoration.

### Changed
- Config field `notify_via_ankrclaw` → `notify_via_webhook`, `ankrclaw_url` → `webhook_url` (old names still accepted via migration shim).
- Default `auto_restart_services` is now `[]` — configure your own services in `enforcement.auto_restart_services`.
- Default `registry_admin_key` is now `null`.
- Dashboard `/commands` page: replaced infrastructure-specific cards with generic AEGIS CLI, Quarantine Management, Agent Management, and KAVACH DAN Gate cards.
- Override token for destructive commands: `# AEGIS-DESTRUCTIVE-CONFIRMED` (was `# HUMAN-DESTRUCTIVE-CONFIRMED-ANKR`).

## [0.1.2] — 2026-04-29

### Added
- **Heartbeat detection** (AEG-T023): session log watcher now classifies each session as `attended` / `unattended` / `abandoned` based on time since last user input. Fires `heartbeat_timeout` alert and SSE event when a session goes abandoned. Respects `heartbeat.action` config (`alert` / `pause` / `kill`). Health endpoint now returns per-session heartbeat mode and idle time. Resumed sessions clear the abandoned state automatically.
- **Slack EE notification channel** (AEG-T042): new `kavach.slack_enabled` + `kavach.slack_webhook_url` config fields. When enabled, sends Block Kit messages to Slack for: budget/anomaly/heartbeat alerts (via enforcer) and KAVACH DAN gate interceptions (via gate). Slack is read-only — responses still go via primary channel (Telegram/WhatsApp). Set `KAVACH_SLACK_WEBHOOK_URL` env var or configure directly in `~/.aegis/config.json`.

### Changed
- Monitor health endpoint (`/health`) now includes `heartbeat.sessions[]` array showing all tracked sessions with `idle_ms` and `mode`.
- `onUserActivity` now clears abandoned state and emits `heartbeat_resumed` SSE event when a user returns to a stale session.

### Known limitations
- Cannot see claude.ai web usage (no public Anthropic API)
- Token-to-USD conversion for Max Plan is approximate (Anthropic doesn't publish exact pricing)
- Mobile device sessions (Termux) only visible if running on the same machine

---

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
