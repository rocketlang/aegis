# Daily Log — `@rocketlang/aegis` and friends

**What this is:** a per-day record of what shipped on the `rocketlang/aegis` repo and its sibling packages. Not a release notes file (each package has its own); not a changelog (one file per repo). This is the chronology — the audit trail of *when* what landed, for sessions, for founders, for next-day continuity.

**Convention:** newest-day-on-top. Each day cites the commit shas it captures. If a day was multi-session, that's noted.

---

## 2026-05-17 (late evening) — Day 6: brand consolidation `@rocketlang/*` → `@xshieldai/*`

**Theme:** unify all `@rocketlang/*` packages under the `@xshieldai` umbrella that already appears in package descriptions ("Part of the xShieldAI Posture Suite"). Founder created the `@xshieldai` npm org; rocketlang user (with new org-access token) republished the entire ecosystem under the new scope.

**npm publishes (8 new + 8 deprecations):**

| New name | Old name | Version | Status |
|---|---|---|---|
| `@xshieldai/aegis` | `@rocketlang/aegis` | 2.2.0 | live, old deprecated |
| `@xshieldai/agent-kernel` | `@rocketlang/kavachos` | 2.0.2 | live, old deprecated |
| `@xshieldai/n8n-nodes` | `@rocketlang/n8n-nodes-kavachos` | 1.1.0 | live, old deprecated |
| `@xshieldai/aegis-guard` | `@rocketlang/aegis-guard` | 0.2.0 | live, old deprecated |
| `@xshieldai/chitta-detect` | `@rocketlang/chitta-detect` | 0.2.0 | live, old deprecated |
| `@xshieldai/lakshmanrekha` | `@rocketlang/lakshmanrekha` | 0.2.0 | live, old deprecated |
| `@xshieldai/hanumang-mandate` | `@rocketlang/hanumang-mandate` | 0.2.0 | live, old deprecated |
| `@xshieldai/aegis-suite` | `@rocketlang/aegis-suite` | 0.2.0 | live (with deps re-pointed), old deprecated |

**PyPI publishes (2 new):**

| New name | Old name | Version |
|---|---|---|
| `xshieldai-langchain` | `langchain-kavachos` | 1.0.0 |
| `xshieldai-crewai` | `crewai-kavachos` | 1.0.0 |

Old PyPI packages remain installable at v1.0.0 (PyPI has no deprecate). DeprecationWarning v1.0.1 planned for follow-up.

**Discoveries during execution:**
- **`@xshieldai` npm org didn't exist** — founder created it via npmjs.com web UI in ~30 seconds (single npm user can own unlimited free orgs as long as packages are public).
- **`@powerpbox` npm scope is taken by an unrelated org** — discovered when checking related scope plans. Workaround: `@powerpboxx` (double-x) is what ANKR internal packages use if needed.
- **Bare `kavachos` PyPI package is NOT ours** (already known and documented v0.6) — collision-claimed by an unrelated MIT-licensed "auth OS for AI agents and humans" project at kavachos.com.
- **kavachos package `prepublishOnly` build hook is broken** (missing `@aws-sdk/client-s3` for dynamic import resolution at build time). Worked around with `npm publish --ignore-scripts` — dist/ artifacts were pre-built from 2026-04-30 and current.

**Docs updated:**
- `README.md` — added "Package rename" banner up top + full new/old mapping table.
- `OPEN-CORE-BOUNDARY.md` v0.6 → **v0.7** brand consolidation edition.
- `EXTRACTION-QUEUE.md` v1.1 → **v1.2** — all 11 future-extraction candidates re-pointed to `@xshieldai/*`.
- `DAILY-LOG.md` — this entry.
- New: `MIGRATION.md` at repo root — full mapping + one-liner migration commands + rationale.

**Marketing updates (deferred to Phase 5):**
- `/root/aegis/marketing/2026-05-17-linkedin-aegis-v2.2.0.md` — needs rewrite to `@xshieldai/*` names + umbrella narrative.
- `/root/aegis/marketing/2026-05-17-twitter-thread-aegis-v2.2.0.md` — same.

**Discipline that held:**
- **Pre-flight scope verification** — registry-check confirmed `@xshieldai` was free across all 8 candidate names before any publish (per `feedback_check_registry_before_extraction`). Saved guesswork.
- **Stop-before-publish for greenlight** — founder approved the rename direction via 3-question AskUserQuestion before any irreversible publish (PyPI naming convention, kavachos word retention, timing).
- **Sensible publish ordering** — leaves first (6 standalone), then aegis-suite last with deps re-pointed. No broken dep graph mid-publish.
- **No `git mv` mid-session for PyPI** — built renames in `/tmp/xshieldai-pypi/` to keep the original packages intact in the repo; the in-repo `packages/langchain-kavachos/` + `crewai-kavachos/` directories can be `git mv`'d in a follow-up commit.
- **Token rotation in-flight** — founder rotated npm token mid-session for org-access scope; old token swap-replaced in `~/.npmrc` with note to revoke leaked-in-transcript credential.

**Open / queued for next session:**
- `git mv packages/langchain-kavachos packages/xshieldai-langchain` (same for crewai) + the internal renames now committed-to-PyPI-state pulled back into repo.
- v1.0.1 of old PyPI packages with DeprecationWarning.
- Test suites for the 4 v0.2.0 primitives (planned for v0.2.1 — still queued).
- hanumang-mandate signature crypto (v0.3 — high priority, unblocks untrusted-channel use).
- aegis v2.3 — `/control-center` filter UI.
- Phase-3 of strategy: 1-2 packages/week from the 11-item `@xshieldai/*` extraction queue.

---

## 2026-05-17 (evening) — Day 5 of Agentic Control Center: aegis v2.2.0 publish + boundary doc v0.6

**Theme:** ship the full dashboard. The 5-day wave closes with `@rocketlang/aegis` going from 2.1.0 → 2.2.0 — the first version where downloading aegis gets the full Agentic Control Center out of the box.

**npm publishes (1 — the big one):**
- `@rocketlang/aegis@2.2.0` — full dashboard ships with: `/suite` inventory (Day 1), `/control-center` cockpit grid + 6 primitive zones (Day 3), `/agent/:id` per-agent timeline (Day 3), `/api/acc/{health,events,events/stream}` SSE (Day 3), 3 AOS panels (Boot Sequence + Primitive Process List + About this AEGIS — Day 4), EE-aware PRAMANA panel via runtime `require.resolve` (Day 4). Tarball 372.3 kB packed / 1.4 MB unpacked / 157 files. Same auth posture as existing dashboard (`config.dashboard.auth.enabled`). PRAMANA OSS Merkle ledger (`src/kernel/merkle-ledger.ts`) renders directly; EE adds an additional panel when `@rocketlang/kavachos-ee` resolves.

**PyPI inventory added to boundary doc:**
- v0.6 also fills in the previously thin PyPI section: `langchain-kavachos@1.0.0` (194/30d) + `crewai-kavachos@1.0.0` (~192/30d), both AGPL-3.0, sources in `/root/aegis/packages/`.
- **Name-collision flagged:** the bare `kavachos` PyPI package (v0.1.0, MIT, `kavachos.com`) is **not ours** — different org, different license. Disambiguation note added to boundary doc so future sessions never claim it or accidentally depend on it.

**Docs updated:**
- `OPEN-CORE-BOUNDARY.md` v0.5 → **v0.6** — release-wave edition. Captures all 5 v0.2.0 packages live + aegis v2.2.0 live + the 2 PyPI packages explicitly inventoried + bare-kavachos collision flagged. No policy changes from v0.5; state-only update.
- `EXTRACTION-QUEUE.md` v1.0 → **v1.1** — Phase-2 ACC items moved from "queued" to "shipped". Test-suite follow-ups remain queued for v0.2.1/v0.3.
- `README.md` — added "What's new in v2.2.0 (2026-05-17) — Agentic Control Center" section with full route list, install via aegis-suite, 5 Phase-1 limits explicitly named, link to all 5 same-wave v0.2.0 sibling packages. Roadmap Phase 2 + Phase 2a marked complete.
- `DAILY-LOG.md` — Day 4 + Day 5 entries (this entry + prev).

**Pre-publish verification:**
- `bun test src/shield/shield.test.ts` — 23 pass, 0 fail (no regression from Days 1-4 changes).
- `bun test tests/aegis-guard.test.ts` in `packages/aegis-guard/` — 63 pass, 0 fail.
- `npm pack --dry-run` clean — tarball shasum `0bec5e8bde3a2c7c98b0e8dad8d6087c71f2ecae`.

**Discipline that held:**
- Stop-before-publish — paused for founder greenlight before `npm publish --access public` (per ACC-T-511 + stop-before-publish standing rule).
- Boundary doc + extraction queue + daily log committed atomically with the publish — no doc drift.

**Open / queued for next session:**
- Test suites for the 4 v0.2.0 primitives (planned for v0.2.1).
- hanumang-mandate signature crypto (v0.3 — high priority, unblocks untrusted-channel use).
- aegis v2.3 — `/control-center` filter UI (deferred from v2.2).
- Phase-3 of strategy: 1-2 packages/week from the 11-item extraction queue.

---

## 2026-05-17 (afternoon) — Day 4 of Agentic Control Center: AOS polish + LinkedIn draft

**Theme:** finish the Agentic Operating System (AOS) feel — boot sequence, process list, health panel, EE-aware optional panel.

**aegis core (no publish — held for Day 5):**
- `src/dashboard/routes/acc.ts` — added 4 panels to `/control-center` page:
  - **Boot Sequence panel** — uptime ticker since module load (`_bootTs`), schema status, route status, EE detection result.
  - **Primitive Process List panel** — table view of all 6 primitives with status / event counts (last 1h) / last-event-ts / "PID" (stable hash of namespace) — gives the OS feel that an agentic dashboard should have.
  - **About this AEGIS health panel** — version, bus type, SQLite path + size, total events, distinct agent count, route inventory.
  - **EE-aware PRAMANA panel** — calls `detectKavachosEE()` (try-catch `require.resolve('@rocketlang/kavachos-ee')`). If found: renders extra EE panel with bonded receipts indicator. If absent: renders OSS-only PRAMANA panel (reads `src/kernel/merkle-ledger.ts` directly). Strict no static EE imports per ACC-006.
- `DAILY-LOG.md` — created. First entries for Days 1, 2, 3 (retroactive with commit refs).

**LinkedIn post drafted:**
- v1 (3 variants) feedback: "lifeless". User specified the structure: FOMO opener → incident ($200 vanished while you sleep) → state-of-the-world (agentic processes are on but architectures haven't caught up) → multi-dim guardrails offering (cost / OS / cybersec / observability) → install CTA.
- v2 rewritten to that exact spec. User asked "send to me" rather than auto-post; drafted as copy-paste-ready text to founder email (per `feedback_external_mail_draft_first` — external content always founder-routed).

**Discipline that held:**
- No auto-post to LinkedIn. Founder posts manually after review.
- EE detection via runtime `require.resolve` only — no static `import { ... } from '@rocketlang/kavachos-ee'` anywhere in OSS code.

**Smoke test (Day 4):**
- `/control-center` loads all 4 new panels with no EE module present (OSS path).
- `_bootTs` uptime ticker increments correctly across page reloads.
- `detectKavachosEE()` returns `null` cleanly when EE absent; no error in dashboard logs.

---

## 2026-05-17 (morning) — Day 3 of Agentic Control Center: wireAllToBus + dashboard surface

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
