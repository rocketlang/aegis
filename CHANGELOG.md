# Changelog

All notable changes to AEGIS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [2.3.0] — 2026-09-25 — the answerability release

> **Can you answer what your agents touched?** This release makes that one command.

### Added (AGPL-3.0)
- **`aegis touched [--since 24h|7d|<ISO>] [--json]`** — the answerability report: per principal,
  what was refused, what the staged invariants observed, what was published under which mandate,
  what tripwires saw, and whether the principal's receipt hash-chain still verifies. The ceiling
  is printed every run: host-computed evidence survives a lying agent, not a compromised host;
  an empty report means nothing *ledgered*, never "nothing happened".
- **`aegis rehearse-chain [--report <out.json>]`** — walks an eleven-step agent-incident chain
  (undeclared egress, credential read, read-then-exfiltrate, unmandated publish, hidden-payload
  SQL at a production target, intrusion tells, staged containment, identity-absent act) against
  the SAME pure decision functions the live hooks run. Strings and synthetic state only; every
  step carries a `live_stage` label so "alerted in shadow" is never dressed as "blocked";
  digest-sealed evidence pack.
- **`aegis quarterly-report [--since 90d] [--out] [--prev] [--dir]`** — the period report:
  answerability leads, then rehearsal, destructive-gate posture, shield/exfil faces, CI audit;
  with `--prev`, the diff opens on regressions first.
- **`aegis publish-mandate grant|list|revoke`** — an outward write (npm/gem/PyPI/docker/release)
  is a gated capability: named, time-bounded consent, and every publish attempt leaves a
  provenance record, permitted or refused. New anumati invariant ships observe-first.
- **`aegis ci-audit [--dir]`** — every publish step in `.github/workflows` must be declared in
  `.github/ankr-ci-declarations.json`; undeclared publishes fail; `uses:` actions are reported
  as a scoped null, never implied coverage.
- **`aegis tripwire-mode | tripwire-clear | tripwire-stage`** — staged containment with a sealed
  mode switch (a hand edit can never arm enforcement), human-only de-escalation with a recorded
  reason, and evidence-gated escalation that never reaches revoke without a verified capture.
- **`aegis redteam --face exfil`** — credential-read + exfil-sequence detectors driven through
  their pure decision cores, with authored scenarios and honest over-flag reporting.
- **Firewall Cockpit** — `/firewall` on the dashboard (behind login): containment mode with a
  typed named-consent flip, tripwire watchlist with clear-with-reason, publish mandates. Every
  button calls the same functions as the CLI.
- New anumati invariants ANU-I-007 (egress capability-over-target), ANU-I-008 (filesystem path
  class), ANU-I-009 (quarantined principal), ANU-I-010 (publish mandate), ANU-I-011 (act-class
  identity) — all enter in observe stage; promotion is a human decision on ledger evidence.

## [2.1.0] — 2026-09-22

### Fixed (KAVACH-KERNEL — AGPL-3.0)
- **Cgroup egress now constrains the agent.** The cgroup is prepared before the launch and the
  agent joins it before `exec`, so membership is inherited through `exec` and by anything it
  spawns. The previous ordering attached by pid after launch, which is the wrong handle: a
  short-lived agent has already exited, and on the notify path the real agent is a fork child
  created before the attach. `cgroup-egress.py --prepare` supervises by cgroup **membership**
  rather than by pid. A failed join is loud — an unconstrained run must never look constrained.
- **Exec allowlist is fail-closed.** The allowlist is parsed once before the fork and validated;
  if `strict_exec` was requested and it cannot be read, the agent does not start. A gate that
  cannot read its own rules refuses. Also removes a JSON parse from the `execve` hot path.
- **Syscall coverage** — `statx`, `rseq`, `prlimit64`, `vfork`, `getppid` added to the baseline.
  Each had a sibling already allowed, so denying them gated nothing and broke ordinary binaries
  (`sh: Cannot fork`, coreutils exiting 2).
- **Build** — `@aws-sdk/client-s3` is a dynamic, optional import and is now marked external
  rather than resolved; the bundle build had been failing on it.

### Added
- **`--needs=PORT,PORT`** — loopback ports an agent legitimately needs, so a broad loopback allow
  can be narrowed. Without it, a deny inside that range is readmitted by the broader rule and is
  therefore decorative; the compiler now says so rather than letting it look enforced.
- **Portable state roots** — `ANKR_CONFIG_DIR`, `ANKR_STATE_DIR`, `AEGIS_HOME`. Defaults unchanged.
  Relocating a root is deliberately **not silent**: these are the files the policy is derived from,
  so a non-default root is printed with every refusal, recorded in the compiled policy, and folded
  into its digest.

### Changed
- Egress goes from never-enforcing to enforcing. This is a real behaviour change for anyone whose
  agents were unconstrained while appearing governed, which is why this is a minor and not a patch.

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
