# AEGIS — Open-Core Boundary Doc

**Status:** v0.6 — release-wave edition. Captures the full @rocketlang ecosystem state after the 5-day Agentic Control Center build wave (2026-05-16 → 2026-05-17). Builds on v0.5's strategic pivot; no policy changes.
**Lives at:** `/root/aegis/OPEN-CORE-BOUNDARY.md` (co-located with code; doc and code change together)
**Companion docs:** `STRATEGY.md` (the why) · `EXTRACTION-QUEUE.md` (the what-next list)
**Audience:** ANKR contributors, future cohort members, anyone deciding "does this go in the AGPL-3.0 OSS package or the BSL-1.1 EE package"

---

## 1. The split, in one paragraph

ANKR is **pre-revenue**. The strategic stance (see `STRATEGY.md`) is **aggressive OSS extraction** until adoption proves the market exists; revenue then follows via domain SaaS (Mari8x / Watch8X / ShipLLM for maritime; potential others for healthcare / finance / defense). **EE exists only for operational leverage** — capabilities that customers literally cannot self-host effectively (multi-tenant hosting, cross-customer baselines, SOC2 packaging, maintained connectors). Everything else is OSS or queued for OSS extraction.

OSS license: **AGPL-3.0-only**. EE license: **BSL-1.1** (4-year Change Date to AGPL-3.0, MariaDB/Sentry/CockroachDB pattern).

---

## 2. What lives where — the real per-package table

### LIVE on npm (AGPL-3.0)

| Package | Version | Downloads (snapshot 2026-05-17) | Role |
|---|---|---|---|
| `@rocketlang/aegis` | **2.2.0** (Day 5) | **869 / 30d** | AEGIS dashboard + KAVACH DAN gate + **Agentic Control Center** (cockpit page at `/control-center` + per-agent timeline at `/agent/:id` + SSE + AOS panels + PRAMANA OSS panel reading existing `src/kernel/merkle-ledger.ts` + EE-aware extra panel via runtime require.resolve). Also contains the OSS PRAMANA Merkle ledger (CT-style), Ed25519-signed STH, S3 anchoring, and SQLite append-only turn-store. |
| `@rocketlang/kavachos` | 2.0.2 | **381 / 30d** | KavachOS — agent BEHAVIOR: seccomp-bpf, Falco, syscall mediation, exec allowlist, egress firewall |
| `@rocketlang/n8n-nodes-kavachos` | 1.1.0 | **144 / 30d** | n8n community nodes |
| `@rocketlang/aegis-guard` | **0.2.0** (Day 2) | **154 / 7d** | Five Locks SDK + opt-in `setEventBus()` for cockpit observability |
| `@rocketlang/chitta-detect` | **0.2.0** (Day 2) | **129 / 7d** | Memory-poisoning detection + opt-in `setEventBus()` (scan.evaluate emits) |
| `@rocketlang/lakshmanrekha` | **0.2.0** (Day 2) | **127 / 7d** | LLM endpoint probe suite + opt-in `setEventBus()` (runProbe emits per probe) |
| `@rocketlang/hanumang-mandate` | **0.2.0** (Day 2) | **143 / 7d** | Mudrika verifier + 7-axis posture scorer + opt-in `setEventBus()` (mudrika + posture events) |
| `@rocketlang/aegis-suite` | **0.2.0** (Day 3) | **116 / 7d** | Meta-package + **`wireAllToBus()`** helper: one call wires all 4 new primitives to a single in-memory bus + SQLite writer at `~/.aegis/acc-events.db` |

### LIVE on PyPI (AGPL-3.0)

| Package | Version | Downloads (snapshot 2026-05-17) | Role |
|---|---|---|---|
| `langchain-kavachos` | 1.0.0 | **194 / 30d** | LangChain callback for KavachOS DAN gate — pre-execution governance via AEGIS. Source: `/root/aegis/packages/langchain-kavachos/`. |
| `crewai-kavachos` | 1.0.0 | **~192 / 30d** | CrewAI integration — DAN gate + budget guard. Source: `/root/aegis/packages/crewai-kavachos/`. |

**Naming disambiguation:** the bare `kavachos` PyPI package (v0.1.0, MIT, `kavachos.com` / `github.com/kavachos/kavachos`, "auth OS for AI agents and humans") is **NOT ours** — a name collision under a different org. Our PyPI presence is the two scoped-by-prefix `*-kavachos` packages only. Never claim or reference the bare `kavachos` package as ours; do not depend on it; if migrating Python users, point them to our prefixed names explicitly.

### EE — BSL-1.1, deliberately not on npm (NARROW after v0.5)

EE is now ~5 items, all genuinely operational:

| Capability | Why it can't be OSS |
|---|---|
| Hosted attestation registry as a service | Needs ANKR-run infrastructure + SLA |
| Multi-tenant isolation in shared deployment | Requires shared infra ANKR pays for |
| Cross-customer baselines (anonymised pooled, with consent) | Requires customer scale + consent flow |
| SOC2 evidence packaging service | Ongoing operational compliance work, regulated-customer specific |
| Maintained connectors (Datadog / Splunk / PagerDuty / Slack-EE) | Ongoing maintenance contract — different from a single OSS Slack notifier primitive |

`@rocketlang/kavachos-ee` v1.0.0 (private distribution to design partners) is the current EE artifact; over v0.6+ its contents narrow as items migrate to OSS per the queue.

### Future OSS — features migrating from EE → OSS (per STRATEGY.md)

These were in the EE pipeline at v0.4. In v0.5 they are reclassified as **OSS extraction candidates** — track them in `EXTRACTION-QUEUE.md`:

| Capability | Current location | Future OSS package | Group |
|---|---|---|---|
| PRAMANA receipt generator | `ee/kavach/pramana-receipts.ts` | `@rocketlang/pramana-receipts` | A |
| HanumanG EE posture registry | `ee/shield/hanumang-ee.ts` | `@rocketlang/hanumang-registry` | A |
| Dual-control approvals | `ee/kavach/*` | `@rocketlang/dual-control` | A |
| Maritime injection signatures | `ee/shield/maritime-signatures.ts` | `@rocketlang/maritime-injection-signatures` | A |
| Slack notifier | `ee/kavach/slack-notifier.ts` | `@rocketlang/slack-notifier` (or merge into aegis) | A |
| Phase-2 Mudrika signature crypto | TBD | next release of `@rocketlang/hanumang-mandate` | A |
| Kubernetes sidecar + admission webhook | TBD | `@rocketlang/k8s-sidecar` | A |
| EU AI Act evidence package (primitive) | TBD | `@rocketlang/eu-ai-act-evidence` (data templates) | A |

The **operational** version of each — hosted, multi-tenant, with SLA — stays EE. The primitive is what moves to OSS.

### Internal-only services (NOT shipped as OSS or EE — operational layer)

| Service | Path | Why internal |
|---|---|---|
| chitta-guard | `/root/chitta-guard/` | Fastify + Prisma + Postgres; depends on 7 closed services. Primitives extracted to `@rocketlang/chitta-detect`. |
| xshieldai-asm-ai-module | `/root/ankrshield/apps/xshieldai-asm-ai-module/` | Service shell; primitives extracted to `@rocketlang/lakshmanrekha`. |
| xshieldai-hanumang | `/root/ankrshield/apps/xshieldai-hanumang/` | Service shell; primitives extracted to `@rocketlang/hanumang-mandate`. |

### Closed (not open-core, not EE-delayed; stays proprietary)

| Asset | Why |
|---|---|
| xshieldai main DRP engine (port 4250, `xshieldai.com`) | Different product line — hosted SaaS |
| 13 paid threat-intel feeds (GreyNoise, OTX, Shodan, etc.) | Cannot redistribute upstream paid credentials |
| Honeypot engine | Operational asset contributing to ANKR's threat intel pool |
| ankrSLM internals, base weights, Layer-1 architecture | **Trade secret** per `[[feedback_slm_trade_secret]]` and `[[feedback_honesty_base_cybersecurity]]`. Never OSS, never EE. Always closed. |
| Mari8x AOS / Watch8X / ShipLLM applications | Domain products — paid SaaS path (future revenue) |
| Other domain applications (healthcare, finance, defense — if pursued) | Same — domain products are revenue, not OSS |

**Read this table as canonical.** When in doubt, this table arbitrates. If something doesn't appear here, the default is *closed*, not open. Opening something is an explicit, recorded decision that updates this table.

---

## 3. License terms — exact

### OSS (`@rocketlang/*` on npm + PyPI)

- **License:** **AGPL-3.0-only**
- **SPDX header on every file:** `// SPDX-License-Identifier: AGPL-3.0-only`
- **Effect:** anyone running OSS as a network service must release modifications. Closes the AWS/Elastic loophole without needing a more restrictive license.

### EE (`@rocketlang/kavachos-ee` + future EE packages)

- **License:** **BSL-1.1**, MariaDB/Sentry/CockroachDB pattern
- **SPDX header:** `// SPDX-License-Identifier: BSL-1.1`
- **Additional Use Grant:** internal business use ≤3 concurrent AI agent sessions free
- **Change Date:** 4 years from a version's first public release
- **Change License:** AGPL-3.0-only — every EE version automatically becomes AGPL-3.0 on its fourth birthday
- **Distribution:** source-available to design partners; not published to npm

### CLA

Required for external contributions. Lets ANKR dual-license contributed code commercially. Without it, contributions cannot legally be bundled into BSL-1.1 EE without AGPL infection.

### Trademark

License-vs-trademark distinction holds. The names **AEGIS, KavachOS, HanumanG, PRAMANA, Mudrika, LakshmanRekha, Chitta, xShieldAI, Mari8x, Watch8X, ShipLLM** are trademarks of rocketlang / Capt. Anil Sharma. Forks must rebrand.

---

## 4. The criteria — how a new feature gets sorted into OSS vs EE

Apply in order. The first one that triggers decides.

1. **Does it require shared infrastructure ANKR pays for?** (Hosted Merkle ledger, multi-tenant registry, paid threat intel feed, SOC2 audit workflow.) → **EE.**
2. **Does it require coordination across multiple customers' data?** (Cross-tenant baselines, federated insights.) → **EE.**
3. **Is it a primitive (a pure library / data set / verifier) or operational infrastructure (a service the customer runs against)?** Primitive → **OSS**. Infrastructure → **EE** if customer needs ANKR to run it; **OSS** if customer can self-host on their own infra.
4. **Does it expose ANKR trade-secret architecture?** (SLM internals, base weights, proprietary classifier architectures.) → **stays closed entirely**, not even EE.
5. **Would a competitor running the OSS-only version still get 80% of the value for their use case?** Yes → keep OSS. No, and adding to OSS would devalue EE → **EE**.
6. **None of the above → OSS.** Default to open when criteria are silent. **The default changed in v0.5** — v0.4 defaulted closed; v0.5 defaults open. This reflects the pre-revenue / aggressive-adoption strategy.

---

## 5. Naming + repo discipline

- **npm scope:** `@rocketlang` (LIVE, ~1,756 monthly downloads across the ecosystem)
- **Package naming:** each primitive gets its own sub-package. Meta-packages group related primitives (e.g., `@rocketlang/aegis-suite` for governance; future `@rocketlang/maritime-suite` for vessel OT).
- **GitHub repo:** monorepo at `github.com/rocketlang/aegis`. `packages/<name>/` per primitive.
- **Internal Verdaccio** at `swayam.digimitra.guru/npm` continues to serve `@ankr/*` packages (~500 today). OSS extraction pulls candidates FROM Verdaccio TO public npm as `@rocketlang/<name>`. The two scopes coexist.
- **NO unscoped packages.** Ever. `kavach` (Wagmi web auth) and `kavachos` (gdsksus AI agent auth) are owned by others; scoping is the safety mechanism.

---

## 6. The HanumanG situation — unchanged from v0.3

Four implementations. Two OSS, one EE, one internal service. Names matter; do not unify.

| Implementation | Location | License | Distribution |
|---|---|---|---|
| OSS spawn-check | `/root/aegis/src/shield/hanumang.ts` | AGPL-3.0 | `@rocketlang/aegis` |
| OSS mudrika + posture scorer | `/root/aegis/packages/hanumang-mandate/src/` | AGPL-3.0 | `@rocketlang/hanumang-mandate` |
| EE registry+posture (migrating to OSS — see §2 future-OSS row) | `/root/aegis/ee/shield/hanumang-ee.ts` | BSL-1.1 now, AGPL-3.0 once extracted | EE only today |
| Internal Fastify service | `/root/ankrshield/apps/xshieldai-hanumang/` | Unlicensed (internal) | Not distributed |

---

## 7. What competitors / forks can and cannot do — unchanged

### Under AGPL-3.0 (OSS packages)

**Can:** fork, run, modify, embed in AGPL-3.0 products, sell consulting / integration. **Cannot:** run as a closed-source network service; strip the license; use trademarks for derivatives without permission.

### Under BSL-1.1 (EE packages)

**Can:** read source; ≤3 concurrent sessions free internal use; non-production; wait 4 years for AGPL-3.0. **Cannot:** production with >3 sessions without commercial license; redistribute as competing managed service.

---

## 8. The EE pipeline — now narrower

Per the v0.5 shrink, EE pipeline contains only operational items:

1. **Hosted attestation registry** as a service — TBD; the SaaS face of PRAMANA, distinct from the open primitive
2. **Multi-tenant fleet dashboard** — TBD; cross-agent posture for n > 10 agents
3. **Replay simulation** — TBD; storage + compute for past-conversation what-ifs
4. **SOC2 evidence packaging** — TBD; ongoing compliance workflow ANKR runs
5. **Maintained connectors** (Datadog / Splunk / PagerDuty / Slack-EE) — partially started, ongoing maintenance

Items previously in the EE pipeline that **moved to OSS-future** are listed in §2 "Future OSS" table and tracked in `EXTRACTION-QUEUE.md`.

---

## 9. The discipline that keeps this honest

Three rules. If any slip, the open-core model loses its meaning.

1. **No EE-shaped feature accidentally lands in OSS.** Every PR that touches `@rocketlang/*` gets reviewed against §4 criteria. If unclear, default OSS (per v0.5 strategic stance).
2. **No OSS-shaped primitive accidentally stays in EE.** Hiding primitives behind a BSL-1.1 paywall when they don't need to be is the failure mode that turned MongoDB into a non-open-core company. EE earns its keep through *operational leverage*, not by gatekeeping primitives.
3. **Trade secrets are off the table for both columns.** SLM internals, base weights, proprietary classifier architectures don't appear in either §2 sub-table. They are not OSS, not BSL-1.1 EE — they are simply not part of this stack.

---

## 10. Resolution path when this doc gets stale

This is v0.5. Every time we publish a new `@rocketlang/*` package, every time a feature moves between OSS and EE, every time the EE table grows or shrinks: **this doc is updated in the same PR**. The boundary doc is not a snapshot; it is the running contract.

If this doc and reality ever diverge, **reality is wrong**, not the doc.

### Version history

- **v0.1** (2026-05-16, morning) — greenfield-shaped; said EE was "commercial EULA"; assumed `@xshieldai` scope. Wrong on three counts. Replaced.
- **v0.2** (2026-05-16, afternoon) — reality-aligned after KAVACH triage. Captured 3 live packages + EE BSL-1.1 reality. §6 added for three-HanumanG situation.
- **v0.3** (2026-05-16, evening) — added 4 packages shipped today: aegis-guard, chitta-detect, lakshmanrekha, hanumang-mandate. §6 updated to FOUR HanumanG implementations.
- **v0.4** (2026-05-16, late evening) — added `@rocketlang/aegis-suite` meta-package. Ecosystem reached 8 packages.
- **v0.5** (2026-05-16, late evening) — **strategic pivot**. Founder is pre-revenue + frugal + intermittent sale revenue + can-survive-forever → aggressive OSS-first is correct. EE shrunk from 16 items to ~5 (operational only). PRAMANA misclassification fixed (was wrongly marked EE in v0.2–v0.4; actually in OSS aegis package — `src/kernel/merkle-ledger.ts`, `merkle-anchor.ts`, `src/telemetry/turn-store.ts`). Default for new features inverted: was "default closed", now "default open". `STRATEGY.md` + `EXTRACTION-QUEUE.md` companion docs created same session.
- **v0.6** (2026-05-17, evening) — **release-wave edition**. Captures the 5-day Agentic Control Center build wave: 5 primitive packages all at v0.2.0 with opt-in `setEventBus()`, `@rocketlang/aegis-suite` v0.2.0 with `wireAllToBus()` helper, `@rocketlang/aegis` v2.2.0 with new `/control-center` + `/agent/:id` + SSE routes + 3 AOS panels + EE-aware PRAMANA extra panel. No policy changes from v0.5 — just state update reflecting what's now live. Build chronology captured in `DAILY-LOG.md`.

---

## 11. Related docs

- **`STRATEGY.md`** — the why behind the v0.5 stance (pre-revenue, frugal, OSS-first)
- **`EXTRACTION-QUEUE.md`** — the running list of OSS extraction candidates from the 500+ Verdaccio + 200+ services
- AEGIS README: `/root/aegis/README.md` (includes Fin Operator parity callout from 2026-05-15)
- AEGIS DOI: 10.5281/zenodo.19625473
- PRAMANA DOI: 10.5281/zenodo.19273330
- CA-006 DOI (LakshmanRekha PROBE-001 source): 10.5281/zenodo.19508513
- `[[feedback_slm_trade_secret]]` — SLM NULL principle
- `[[feedback_honesty_base_cybersecurity]]` — never inflate V
- `[[feedback_check_registry_before_extraction]]` — registry-check-first discipline
- `[[project_rocketlang_npm_campaign_2026_05_16]]` — the campaign that produced today's 5 new packages

---

*End of boundary doc v0.5. ~2,500 words. Lives at `/root/aegis/OPEN-CORE-BOUNDARY.md`. Updated 2026-05-16 late evening alongside STRATEGY.md + EXTRACTION-QUEUE.md.*
