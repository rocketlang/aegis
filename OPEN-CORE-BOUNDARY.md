# AEGIS — Open-Core Boundary Doc

**Status:** v0.2 — replaces v0.1 (which was at `/root/ankrshield/OPEN-CORE-BOUNDARY.md` and was greenfield-shaped, BSL-licensing-wrong, scope-name-wrong)
**Drafted:** 2026-05-16
**Lives at:** `/root/aegis/OPEN-CORE-BOUNDARY.md` (co-located with the code; the doc and the code change together)
**Audience:** ANKR contributors, future cohort members, anyone deciding "does this go in the AGPL-3.0 OSS package or the BSL-1.1 EE package"

---

## 1. The split, in one paragraph

Everything that lives on **`npmjs.com/@rocketlang/*`** is **AGPL-3.0-only** open source — primitives that any developer can `npm install`, self-host, modify, and redistribute, with the AGPL clause-13 requirement that network-service modifications be released back. Everything that lives in **`/root/aegis/ee/`** is **BSL-1.1** (Business Source License, 4-year delayed-AGPL conversion) — published in source form to design partners under a commercial agreement, automatically converting to AGPL-3.0 four years after the version's first public release. Both halves are part of one coherent governance stack: **AEGIS (spend) / KavachOS (behavior) / PRAMANA (attestation)**.

This is the same shape Sentry, MariaDB, CockroachDB use — BSL with a Change Date, not a perpetual-commercial EULA. The discipline is that EE is **eventually open**, not forever closed.

---

## 2. What lives where — the real per-package table

### LIVE on npm (AGPL-3.0)

| Package | Version | Downloads (30d as of 2026-05-16) | Role |
|---|---|---|---|
| `@rocketlang/aegis` | 2.1.0 | **859** | AEGIS — agent SPEND governance: budget caps, kill-switch, DAN gate, HanumanG 7-axis spawn check |
| `@rocketlang/kavachos` | 2.0.2 | **370** | KavachOS — agent BEHAVIOR: seccomp-bpf, Falco, syscall mediation, exec allowlist, egress firewall |
| `@rocketlang/n8n-nodes-kavachos` | 1.1.0 | **143** | n8n community nodes — DAN gate / kernel enforcement / budget check / audit log |

### Code-complete but unpublished (will be AGPL-3.0)

| Package | Status | Blocker |
|---|---|---|
| `@rocketlang/aegis-guard` (currently `@ankr/aegis-guard` in `package.json`) | v0.1.0 code ready | Scope rename + publish (task #18) |
| `@rocketlang/langchain-kavachos` | code present, package.json missing | Finish packaging + publish (task #19) |
| `@rocketlang/crewai-kavachos` | code present, package.json missing | Finish packaging + publish (task #20) |
| `@rocketlang/lakshmanrekha` | source lives in `/root/ankrshield/apps/xshieldai-asm-ai-module/` — needs extraction into aegis monorepo | Cross-repo move (task #17) |

### Standalone services to fold or deprecate

| Asset | Today | Decision pending |
|---|---|---|
| `xshieldai-hanumang` (Fastify service, `@ankrshield/xshieldai-hanumang` v0.1.0, never published) | Separate JWT-mandate-verification implementation; different axes than aegis OSS HanumanG | Task #21 — merge into `@rocketlang/aegis` as Phase 2 axes (current lean), keep standalone, or deprecate |

### EE — BSL-1.1, deliberately not on npm

| Package | Version | Distribution | What it contains |
|---|---|---|---|
| `@rocketlang/kavachos-ee` | 1.0.0 | Private, source-available to design partners (`captain@ankr.in`) | PRAMANA Merkle ledger, HanumanG EE posture registry (domain registry + GREEN/AMBER/RED scoring + dominant_failure), dual-control approvals, maritime injection signatures, multi-tenant isolation |

### Closed (not open-core, not EE-delayed; stays proprietary)

| Asset | Why |
|---|---|
| xshieldai main DRP engine (port 4250, `xshieldai.com`) | Different product line — domain risk, phone, typosquat, spyware, IOC. Hosted SaaS. Not in this stack's scope. |
| 13 paid threat-intel feeds (GreyNoise, OTX, Shodan, etc.) | Cannot redistribute upstream paid credentials |
| Honeypot engine | Operational asset contributing to ANKR's threat intel pool |
| ankrSLM internals | Trade secret per `[[feedback_slm_trade_secret]]` and `[[feedback_honesty_base_cybersecurity]]` |

**Read this table as the canonical "what lives where" — when in doubt, this table arbitrates.** If something doesn't appear here, the default is *closed*, not open. Opening something is an explicit, recorded decision.

---

## 3. License terms — exact

### OSS (`@rocketlang/*` published to npm)

- **License:** **AGPL-3.0-only** (not AGPL-3.0-or-later).
- **SPDX header on every file:** `// SPDX-License-Identifier: AGPL-3.0-only`
- **Effect:** anyone running the OSS as a network service must release modifications. Closes the AWS/Elastic loophole.

### EE (`@rocketlang/kavachos-ee` + future EE packages)

- **License:** **BSL-1.1** (Business Source License 1.1, the standard MariaDB/Sentry/CockroachDB pattern).
- **SPDX header on every file:** `// SPDX-License-Identifier: BSL-1.1`
- **Additional Use Grant:** internal business use with **up to 3 concurrent AI agent sessions** is free. Production deployments with >3 concurrent sessions require a commercial license.
- **Change Date:** **4 years** from a version's first public release.
- **Change License:** AGPL-3.0-only. So every EE version automatically becomes AGPL-3.0 on its fourth birthday.
- **Distribution:** source-available to design partners under commercial agreement; **NOT published to npm**; explicit `_distribution: "private — not published to npm"` field in `ee/package.json`.

### Contributor License Agreement (CLA)

- **Required for all external contributions** to AGPL-3.0 OSS packages.
- The CLA grants the Licensor (Capt. Anil Sharma / rocketlang) the right to relicense contributed code commercially. This is the *only* legal mechanism that lets contributed OSS code be bundled into the BSL-1.1 EE without AGPL infection.
- CLA template TBD; for now contributions are by founder + named cohort members only.

### Trademark

- License-vs-trademark is a real distinction. The licenses above govern source. The names **AEGIS**, **KavachOS**, **HanumanG**, **PRAMANA**, **xShieldAI** are trademarks of rocketlang / Capt. Anil Sharma. Forks must rebrand to avoid trademark dilution.

---

## 4. The criteria — how a new feature gets sorted into OSS vs EE

Apply in order. The first one that triggers decides.

1. **Does it require shared infrastructure ANKR pays for?** (Hosted Merkle ledger, multi-tenant registry, paid threat intel feed.) → **EE.** OSS can't ship infrastructure dependencies.
2. **Does it require coordination across multiple customers' data?** (Cross-tenant baselines, shared corpora, federated insights.) → **EE.** OSS is single-tenant by definition.
3. **Is it the primitive itself, or a convenience wrapper / posture-scoring layer / registry around the primitive?** Primitive → **OSS**. Wrapper/registry/scoring → **EE** if it provides multi-session insight; OSS if it's per-session telemetry.
4. **Does it expose ANKR trade-secret architecture?** (SLM internals, base weights, proprietary classifier architectures.) → **stays closed entirely**, not even in EE. Per `[[feedback_slm_trade_secret]]`.
5. **Would a competitor running the OSS-only version still get 80% of the value for their use case?** If yes → keep it OSS (don't artificially cripple). If no, and adding it to OSS would devalue EE → **EE**.
6. **None of the above triggered → OSS.** Default to open when criteria are silent.

The criteria are designed so primitives default to open and operational leverage defaults to delayed-open (BSL-1.1).

---

## 5. Naming + repo discipline

- **npm scope:** `@rocketlang` (LIVE, has 859/370/143 monthly downloads across three packages — do not fragment).
- **NOT `@xshieldai`** — that scope is unclaimed and was a draft proposal in v0.1 of this doc; it would fragment the existing brand and lose the download history.
- **Package naming:** each primitive gets its own sub-package. `@rocketlang/aegis` (parent + spend), `@rocketlang/kavachos` (behavior), `@rocketlang/lakshmanrekha` (planned), `@rocketlang/aegis-guard` (planned), etc.
- **GitHub repo:** monorepo at `github.com/rocketlang/aegis`. `packages/<name>/` per primitive. One PR can fix cross-package issues.
- **NO unscoped packages.** Ever. The unscoped `kavach` (web auth, Wagmi) and `kavachos` (different AI agent auth, gdsksus@kavachos.com) are owned by other developers; scoping is the safety mechanism.
- **Mythological-name discipline:** `@rocketlang/varuna` would be our Varuna (maritime OT). `@rocketlang/kavach` and `@rocketlang/kavachos` are *our* names within the scope, distinct from the unscoped collisions. Scope prefix makes them unambiguous.

---

## 6. The three-HanumanG situation — read this before touching HanumanG

The codebase contains **three HanumanG implementations**. They share a name and a "7 axes" framing but solve different problems and live in different places. Do not unify or refactor across them without explicit founder approval.

| Implementation | Location | License | Axes | Problem it solves |
|---|---|---|---|---|
| **OSS spawn-check** | `/root/aegis/src/shield/hanumang.ts` | AGPL-3.0 | identity / authorization / scope / budget / depth / purpose / revocability | Runtime: block bad agent spawns at PreToolUse |
| **EE registry+posture** | `/root/aegis/ee/shield/hanumang-ee.ts` | BSL-1.1 | OSS axes + domain registry validation + GREEN/AMBER/RED scoring | Adds agent-type registry + session-history posture |
| **Standalone JWT-mandate service** | `/root/ankrshield/apps/xshieldai-hanumang/` | unlicensed (Fastify service) | mudrika_integrity / identity_broadcast / mandate_bounds / proportional_force / return_with_proof / no_overreach / truthful_report | JWT-mandate verification; different problem |

The OSS + EE pair (rows 1 + 2) is the production aegis stack. The standalone (row 3) is an exploratory parallel implementation that may merge into the OSS Phase 2 (task #21).

**When writing about HanumanG externally**, default to the OSS spawn-check unless the context specifically requires the JWT-mandate framing. The 7-axis paper that ships with the README points at row 1.

---

## 7. What competitors / forks can and cannot do

### Under AGPL-3.0 (OSS packages)

**Can:**
- Fork any `@rocketlang/*` package and run it forever, modified or unmodified.
- Build derivative products, *provided* network-service modifications are released under AGPL-3.0 (clause 13).
- Sell consulting / integration services around the OSS packages.
- Embed in their own products if their products also ship under AGPL-3.0 (or they obtain a CLA-backed commercial dual-license from rocketlang).

**Cannot:**
- Run `@rocketlang/*` as a closed-source network service. AGPL-3.0 forbids it.
- Strip the AGPL-3.0 license and republish under a different license without CLA-backed permission.
- Use the AEGIS / KavachOS / HanumanG / PRAMANA trademarks for a derivative product without permission.

### Under BSL-1.1 (EE packages)

**Can:**
- Read and modify the source code (it is source-available, not "free open source").
- Use it for internal business purposes with up to 3 concurrent AI agent sessions, free.
- Make non-production use (development, testing, evaluation).
- Wait 4 years from a version's release and use it under AGPL-3.0.

**Cannot:**
- Run as a production service with >3 concurrent agent sessions without a commercial license.
- Redistribute as a competing managed service while still under BSL-1.1.
- Strip the BSL-1.1 license.

This is what BSL-1.1 buys us: a 4-year commercial protection window during which we can build a business on the EE, after which the code becomes fully open. It is the honest middle ground between "forever closed" and "free immediately."

---

## 8. The EE candidate pipeline — what is planned for BSL-1.1 EE

These are NOT in OSS, are NOT yet built (or are partially built) in EE. They are explicit BSL-1.1 EE candidates:

1. **PRAMANA Merkle ledger** — partially in `@rocketlang/kavachos-ee` v1.0.0; cryptographic attestation chain
2. **HanumanG EE posture registry** — in `kavachos-ee` v1.0.0; domain registry + posture scoring across session history
3. **Dual-control approvals** — in `kavachos-ee` v1.0.0
4. **Maritime injection signatures** — in `kavachos-ee` v1.0.0
5. **Multi-tenant isolation** — in `kavachos-ee` v1.0.0
6. **Hosted attestation registry as a service** — TBD; the SaaS face of PRAMANA
7. **Multi-agent fleet dashboard** — TBD; cross-agent posture view (n > 10 agents)
8. **Replay simulation** — TBD; re-run past conversations against candidate policy changes
9. **Connectors** (Datadog / Splunk / PagerDuty / Slack-EE) — partially started (`ee/kavach/slack-notifier.ts`)
10. **SOC2 evidence packs** — TBD; automatic audit-ready evidence
11. **Cross-customer baselines** (anonymised pooled) — TBD; with explicit consent
12. **xshieldai-main, threat-intel feeds, honeypot engine** — explicitly listed in §2 closed table; NOT BSL-1.1 candidates; stay proprietary

When any of these gets built, the table in §2 is updated.

---

## 9. The discipline that keeps this honest

Three rules. If any of these slip, the open-core model loses its meaning.

1. **No EE-shaped feature accidentally lands in OSS.** Every PR that touches `@rocketlang/*` gets reviewed against §4 criteria. If unclear, default closed.
2. **No OSS-shaped primitive accidentally stays in EE.** Hiding primitives behind a BSL-1.1 paywall when they don't need to be is the failure mode that turned MongoDB into a non-open-core company. EE earns its keep through *operational leverage*, not by gatekeeping primitives.
3. **Trade secrets are off the table for both columns.** SLM internals, base weights, proprietary classifier architectures don't appear in either §2 sub-table. They are not OSS, not BSL-1.1 EE — they are simply not part of this stack. Per `[[feedback_slm_trade_secret]]` and `[[feedback_honesty_base_cybersecurity]]`.

---

## 10. Resolution path when this doc gets stale

This is v0.2. Every time we publish a new `@rocketlang/*` package, every time a feature moves between OSS and EE, every time the EE table grows: **this doc is updated in the same PR**. The boundary doc is not a snapshot; it is the running contract.

If this doc and reality ever diverge, **reality is wrong**, not the doc. The doc is the authoritative source. Code that contradicts the doc is the thing that needs fixing.

### Version history

- **v0.1** (2026-05-16, morning) — greenfield-shaped; said EE was "commercial EULA"; assumed `@xshieldai` scope. Wrong on three counts: (a) project is not greenfield (aegis already v2.1.0 with 859 monthly downloads), (b) EE is BSL-1.1 with 4-year Change Date, not commercial EULA, (c) scope is `@rocketlang`. Replaced by v0.2.
- **v0.2** (2026-05-16, afternoon) — this version. Reality-aligned after KAVACH triage discovered the live ecosystem.

---

## 11. Related docs

- AEGIS README: `/root/aegis/README.md`
- AEGIS DOI: 10.5281/zenodo.19625473
- PRAMANA DOI: 10.5281/zenodo.19273330
- xShieldAI capability overview: `/root/xshieldai-capability-overview-2026-05-16.txt`
- `[[feedback_slm_trade_secret]]` — SLM NULL principle, never disclose architecture
- `[[feedback_honesty_base_cybersecurity]]` — never inflate V, LakshmanRekha + HanumanG + Report Card discipline
- `[[feedback_frugal_slm_strategy]]` — SLM is reasoning, RAG is knowledge, LoRA is adaptation
- Codex: `/root/aegis/codex.json` + `/root/ankrshield/codex.json` + per-service codex files

---

*End of boundary doc v0.2. ~2,100 words. Lives at `/root/aegis/OPEN-CORE-BOUNDARY.md`. Updated with every npm publish or every cross-boundary feature move. v0.1 at `/root/ankrshield/OPEN-CORE-BOUNDARY.md` is superseded — to be replaced with a one-line pointer to this file.*
