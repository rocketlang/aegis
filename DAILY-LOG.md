# Daily Log — `@rocketlang/aegis` and friends

**What this is:** a per-day record of what shipped on the `rocketlang/aegis` repo and its sibling packages. Not a release notes file (each package has its own); not a changelog (one file per repo). This is the chronology — the audit trail of *when* what landed, for sessions, for founders, for next-day continuity.

**Convention:** newest-day-on-top. Each day cites the commit shas it captures. If a day was multi-session, that's noted.

---

## 2026-05-17 — Day 3 of Agentic Control Center: wireAllToBus + dashboard surface

**Theme:** wire the 4 v0.2.0 primitives into a consolidated event bus + render them in a cockpit page.

**npm publishes (1):**
- `@rocketlang/aegis-suite@0.2.0` — meta-package now ships `wireAllToBus()` helper + self-contained `InMemoryBus` + `SqliteEventWriter`. One call wires all 4 OSS primitives to a single bus persisting to `~/.aegis/acc-events.db`. Tarball 9.9 kB / 6 files. Commit `364cc55`.

**aegis core (no publish — Day 5):**
- `src/acc/bus.ts` — dashboard-side reader (queries SQLite for zone rendering, SSE polling, agent timeline).
- `src/dashboard/routes/acc.ts` — full rewrite. Added: `/control-center` (single-page grid, 6 primitive zones + PRAMANA panel), `/agent/:id` (per-agent timeline), `/api/acc/health`, `/api/acc/events`, `/api/acc/events/stream` (SSE). Day 1's `/suite` unchanged.
- `package.json` — added `./acc/bus` and `./acc/types` exports. Version stays at 2.1.0 until Day 5's full publish.
- Commit `496611a`.

**Smoke tests passed:**
1. Consumer-shape script calls `wireAllToBus()`, runs 7 primitive ops → all land in SQLite correctly.
2. Dashboard at port 4860 (test config, auth disabled) renders `/control-center` with correct zone counts matching SQLite.
3. Same dashboard with `auth.enabled: true` correctly 302→/login when unauthenticated; serves the page after login.
4. Cross-process verified: consumer writes to SQLite in one process, dashboard reads from same file in another (with `handle.checkpoint()` for immediate WAL visibility).

**False alarm caught + resolved:**
- During Smoke #2, `/control-center` returned 200 unauthenticated. Initial fear: new routes bypassing auth. Reality: test config didn't enable `dashboard.auth.enabled`. Production config DOES (`~/.aegis/config.json` has `auth.enabled: true`). New routes inherit identical auth posture to existing dashboard. No code defect.

**Discipline that held:**
- Stop-before-publish for greenlight (1 publish, founder-approved).
- Each smoke test concrete (real SQL queries, real HTTP, real cookies) — not just trusting that pieces compile.
- Founder-discovered naming entanglement in mid-day: aegis-cockpit was already public-conflicted with `ankr-command-center`, `ankr-cockpit-react`. Renamed entire feature to **Agentic Control Center (ACC)** before Day 2 publishes — clean break, no leaked names.

**Open / queued:**
- Day 4: AOS polish (boot panel, primitive-process-list, uptime/health, EE-aware PRAMANA panel).
- Day 5: bump `@rocketlang/aegis` to v2.2.0 + publish + final OPEN-CORE-BOUNDARY.md update.

---

## 2026-05-16 — Day 2 of Agentic Control Center: v0.2.0 for 4 primitives

**Theme:** add opt-in `setEventBus()` API to each primitive. Stateless contract preserved — no bus = no emit, identical to v0.1.0.

**npm publishes (4):**
- `@rocketlang/aegis-guard@0.2.0` — Five Locks now emit `lock.approval.verified` / `lock.approval.rejected` / `lock.nonce.consumed` / `lock.nonce.rejected` / `lock.idempotency.duplicate` / `lock.idempotency.mismatch` / `lock.sense.emitted`. 11.4 kB. Commit `f093a58`.
- `@rocketlang/chitta-detect@0.2.0` — `scan.evaluate()` emits `scan.evaluated` per scan with verdict (PASS / ADVISORY / INJECT_SUSPECT / BLOCK). Individual detector primitives don't emit independently (would flood the bus). 13.6 kB. Commit `c9e9279`.
- `@rocketlang/lakshmanrekha@0.2.0` — `runProbe()` emits `probe.run` per probe with verdict (refused / complied / partial / inconclusive / errored). API key never in receipts; endpoint logged as host only. 12.4 kB. Commit `a841336`.
- `@rocketlang/hanumang-mandate@0.2.0` — mudrika verifier emits `mudrika.verified` / `mudrika.rejected`; per-axis `posture.axis_scored`; aggregate `posture.scored` with A-F grade. 10.2 kB. Commit `34a33d1`.

**Discipline:**
- Each publish individually greenlit by founder (4 stop-before-publish rounds).
- Each primitive's existing test suite passed unchanged after wiring (stateless contract verified).
- Each README updated with Phase-1 limits explicitly named (agent_id population gaps, pure helpers not emitted, signature crypto deferred).
- Smoke tests caught one real bug — hanumang-mandate `EXPIRED` mudrika path wasn't emitting; fixed before publish.

**Foundation work earlier in same day:**
- Methodology gate (R-012) walked properly: brainstorm → project → logics (27 rules) → requirements (req_mask=12527821) → vivechana (V=25,088) → todo (33 tasks). Commit `b2639442`.
- Renamed feature `aegis-cockpit` → **Agentic Control Center (ACC)** before any Day 2 publishes. Rule prefix COCKPIT-* → ACC-*. Six docs renamed + 3 code files renamed in two commits (`15fe4d45` and `420741a`).
- Day 1 (`/suite` inventory page) shipped earlier — commit `69f9886`.

---

## 2026-05-16 (earlier same day) — Strategic pivot + 4-package shipping campaign + cohort frame

**Theme:** Multiple parallel threads. Pre-revenue strategic pivot locked. 4 new npm primitives published. Founding cohort frame committed.

**npm publishes (5):**
- `@rocketlang/aegis-guard@0.1.0` — Five Locks SDK extracted from carbonx-backend. 8.7 kB.
- `@rocketlang/chitta-detect@0.1.0` — memory poisoning detection primitives extracted from chitta-guard. 11.8 kB.
- `@rocketlang/lakshmanrekha@0.1.0` — LLM endpoint probe suite extracted from xshieldai-asm-ai-module. 10.6 kB.
- `@rocketlang/hanumang-mandate@0.1.0` — mudrika + 7-axis posture scorer extracted from xshieldai-hanumang. 8.2 kB.
- `@rocketlang/aegis-suite@0.1.0` — meta-package bundling the 6 OSS primitives (aegis + kavachos + 4 new). 4.8 kB.

**Strategic docs (3 new):**
- `OPEN-CORE-BOUNDARY.md` v0.5 — EE shrunk from 16 items to ~5 (operational only); PRAMANA misclassification corrected (was wrongly EE in v0.2–v0.4, actually OSS in `src/kernel/merkle-ledger.ts`); default for new features flipped from closed→open.
- `STRATEGY.md` v1.0 — locked: pre-revenue + frugal + intermittent sale income = patient capital = aggressive OSS until adoption proves market; domain SaaS as eventual revenue, not EE feature gating.
- `EXTRACTION-QUEUE.md` v1.0 — 10 seed candidates for future OSS extraction from 500+ Verdaccio + 200+ services.

**Cohort frame:**
- Founding cohort = 2: Saurabh (Founding Apprentice) + Bhargavi (Founding Returner). Zero cash, sweat-equity.
- 3 founding docs committed in `/root/apprentice-maritime/`: founding-cohort-memo + Saurabh Days 1-3 co-host playbook + Bhargavi CodeAI101 returner-review playbook.

**README repositioning:**
- `@rocketlang/aegis` README added Fin Operator parity callout — Intercom (now "Fin") launched their "proposal system" subscription product 2026-05-15; aegis predates by ~1 month with the same architectural primitives (pull-request-shaped intercept, agent-managing-agent, attestation chain). Open primitives vs hosted subscription.

**Discovery in same day:**
- `langchain-kavachos` + `crewai-kavachos` were already on PyPI (192/30d each) — published 2026-05-01, forgotten. Verified before what would have been duplicate work.

---

## Why this log exists

ANKR is a multi-session, AI-assisted build. Each session loses context unless we externalise it. Per **Founding Principle F** (Capture Everything — fighting AI amnesia): the daily log is the cross-session continuity layer for the @rocketlang ecosystem.

Reading this log, a new session knows:
- What's live on npm + what version
- What's in tree but not yet published
- What discipline was applied and what was caught
- What's open / queued for tomorrow

The log is append-only-forward (newest day on top); existing entries get small **session note** additions if a later discovery changes the picture, never silent rewrites.
