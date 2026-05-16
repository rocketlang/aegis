# AEGIS — Open-Core Boundary Doc

**Status:** v0.3 — reflects the 4-package campaign of 2026-05-16. Supersedes v0.2.
**Lives at:** `/root/aegis/OPEN-CORE-BOUNDARY.md` (co-located with code; doc and code change together)
**Audience:** ANKR contributors, future cohort members, anyone deciding "does this go in the AGPL-3.0 OSS package or the BSL-1.1 EE package"

---

## 1. The split, in one paragraph

Everything that lives on **`npmjs.com/@rocketlang/*`** is **AGPL-3.0-only** open source — primitives that any developer can `npm install`, self-host, modify, and redistribute, with the AGPL clause-13 requirement that network-service modifications be released back. Everything that lives in **`/root/aegis/ee/`** is **BSL-1.1** (Business Source License, 4-year delayed-AGPL conversion) — published in source form to design partners under a commercial agreement, automatically converting to AGPL-3.0 four years after the version's first public release. Both halves are part of one coherent governance stack: **AEGIS (spend) / KavachOS (behavior) / PRAMANA (attestation)** + four primitive packages shipped 2026-05-16.

This is the same shape Sentry, MariaDB, CockroachDB use — BSL with a Change Date, not a perpetual-commercial EULA. The discipline is that EE is **eventually open**, not forever closed.

---

## 2. What lives where — the real per-package table

### LIVE on npm (AGPL-3.0)

| Package | Version | Downloads (30d, 2026-05-16) | Role |
|---|---|---|---|
| `@rocketlang/aegis` | 2.1.0 | **859** | AEGIS — agent SPEND governance: budget caps, kill-switch, DAN gate, HanumanG 7-axis spawn check |
| `@rocketlang/kavachos` | 2.0.2 | **370** | KavachOS — agent BEHAVIOR: seccomp-bpf, Falco, syscall mediation, exec allowlist, egress firewall |
| `@rocketlang/n8n-nodes-kavachos` | 1.1.0 | **143** | n8n community nodes — DAN gate / kernel enforcement / budget check / audit log |
| `@rocketlang/aegis-guard` | 0.1.0 | new (2026-05-16 09:59 UTC) | Five Locks SDK — approval-token, nonce, idempotency, SENSE emit, quality evidence (from carbonx) |
| `@rocketlang/chitta-detect` | 0.1.0 | new (2026-05-16 10:46 UTC) | Memory-poisoning detection primitives (8 namespaces: trust, imperative, toolOutput, capabilityExpansion, fingerprint, rateLimit, retrospective, scan) — extracted from chitta-guard |
| `@rocketlang/lakshmanrekha` | 0.1.0 | new (2026-05-16 12:00 UTC) | LLM endpoint probe suite (8 probes + deterministic refusal classifier + multi-provider runner) — extracted from xshieldai-asm-ai-module |
| `@rocketlang/hanumang-mandate` | 0.1.0 | new (2026-05-16 12:30 UTC) | Mudrika delegation-credential verifier + 7-axis posture scorer — extracted from xshieldai-hanumang |

**Total monthly downloads across @rocketlang npm (as of campaign):** ~1,372 (older 3) + 0 (new 4). New packages start at 0 by definition; expect adoption to compound over the next 30 days.

### LIVE on PyPI (AGPL-3.0)

| Package | Version | Downloads (30d) | Role |
|---|---|---|---|
| `langchain-kavachos` | 1.0.0 | **192** | LangChain integration for KavachOS gates |
| `crewai-kavachos` | 1.0.0 | **192** | CrewAI integration (depends on langchain-kavachos) |

Both published 2026-05-01 — discovered in this campaign to already have traction.

### EE — BSL-1.1, deliberately not on npm

| Package | Version | Distribution | What it contains |
|---|---|---|---|
| `@rocketlang/kavachos-ee` | 1.0.0 | Private, source-available to design partners (`captain@ankr.in`) | PRAMANA Merkle ledger, HanumanG EE posture registry (domain registry + GREEN/AMBER/RED scoring + dominant_failure), dual-control approvals, maritime injection signatures, multi-tenant isolation |

### Internal-only services (NOT shipped as OSS or EE — operational layer)

| Service | Path | Why not OSS |
|---|---|---|
| chitta-guard | `/root/chitta-guard/` | Fastify + Prisma + Postgres; depends on 7 closed services. Primitives extracted to `@rocketlang/chitta-detect`. |
| xshieldai-asm-ai-module | `/root/ankrshield/apps/xshieldai-asm-ai-module/` | Fastify + SQLite; primitives extracted to `@rocketlang/lakshmanrekha`. |
| xshieldai-hanumang | `/root/ankrshield/apps/xshieldai-hanumang/` | Fastify + SQLite + 5 service deps; primitives extracted to `@rocketlang/hanumang-mandate`. |

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

### OSS (`@rocketlang/*` on npm + PyPI)

- **License:** **AGPL-3.0-only**
- **SPDX header on every file:** `// SPDX-License-Identifier: AGPL-3.0-only`
- **Effect:** anyone running OSS as a network service must release modifications. Closes the AWS/Elastic loophole.

### EE (`@rocketlang/kavachos-ee` + future EE packages)

- **License:** **BSL-1.1**, standard MariaDB/Sentry/CockroachDB pattern.
- **SPDX header:** `// SPDX-License-Identifier: BSL-1.1`
- **Additional Use Grant:** internal business use with **up to 3 concurrent AI agent sessions** is free. Production deployments with >3 concurrent sessions require a commercial license.
- **Change Date:** **4 years** from a version's first public release.
- **Change License:** AGPL-3.0-only. Every EE version automatically becomes AGPL-3.0 on its fourth birthday.
- **Distribution:** source-available to design partners; **NOT published to npm**.

### CLA

Required for external contributions. Lets ANKR dual-license contributed code for commercial use; without it, contributions cannot legally be bundled into BSL-1.1 EE without AGPL infection.

### Trademark

License-vs-trademark distinction holds. The names **AEGIS, KavachOS, HanumanG, PRAMANA, Mudrika, LakshmanRekha, Chitta, xShieldAI** are trademarks of rocketlang / Capt. Anil Sharma. Forks must rebrand.

---

## 4. The criteria — how a new feature gets sorted into OSS vs EE

Apply in order. The first one that triggers decides.

1. **Does it require shared infrastructure ANKR pays for?** (Hosted Merkle ledger, multi-tenant registry, paid threat intel feed.) → **EE.**
2. **Does it require coordination across multiple customers' data?** (Cross-tenant baselines, federated insights.) → **EE.**
3. **Is it the primitive itself, or a convenience wrapper / posture-scoring layer / registry around the primitive?** Primitive → **OSS**. Wrapper/registry/scoring → **EE** if multi-session insight; OSS if per-session telemetry.
4. **Does it expose ANKR trade-secret architecture?** (SLM internals, base weights, proprietary classifier architectures.) → **stays closed entirely**, not even EE. Per `[[feedback_slm_trade_secret]]`.
5. **Would a competitor running the OSS-only version still get 80% of the value for their use case?** Yes → keep OSS. No, and adding to OSS would devalue EE → **EE**.
6. **None of the above → OSS.** Default to open when criteria are silent.

---

## 5. Naming + repo discipline

- **npm scope:** `@rocketlang` (LIVE, has ~1,372+ monthly downloads on older 3 packages alone — do not fragment).
- **NOT `@xshieldai`** — that scope was a draft proposal that v0.1 of this doc considered and v0.2 ruled out.
- **Package naming:** each primitive gets its own sub-package. Today's campaign added 4 → ecosystem now 7 packages.
- **GitHub repo:** monorepo at `github.com/rocketlang/aegis`. `packages/<name>/` per primitive.
- **NO unscoped packages.** Ever. The unscoped `kavach` (web auth, Wagmi) and `kavachos` (different AI agent auth, gdsksus@kavachos.com) are owned by other developers; scoping is the safety mechanism.

---

## 6. The HanumanG situation — read this before touching HanumanG

The codebase contains **multiple HanumanG implementations**. They share a name but solve different problems. Do not unify or refactor across them without explicit founder approval.

| Implementation | Location | License | Distribution | Axes | Problem it solves |
|---|---|---|---|---|---|
| **OSS spawn-check** | `/root/aegis/src/shield/hanumang.ts` | AGPL-3.0 | npm `@rocketlang/aegis` v2.1.0 | identity / authorization / scope / budget / depth / purpose / revocability | Runtime: block bad agent spawns at PreToolUse |
| **OSS mudrika + posture scorer** *(new 2026-05-16)* | `/root/aegis/packages/hanumang-mandate/src/` | AGPL-3.0 | npm `@rocketlang/hanumang-mandate` v0.1.0 | mudrika_integrity / identity_broadcast / mandate_bounds / proportional_force / return_with_proof / no_overreach / truthful_report | Mandate verification + per-action posture grade |
| **EE registry+posture** | `/root/aegis/ee/shield/hanumang-ee.ts` | BSL-1.1 | EE only (`@rocketlang/kavachos-ee`) | Spawn-check axes + domain registry validation + GREEN/AMBER/RED scoring | Adds agent-type registry + session-history posture across multiple agents |
| **Internal Fastify service** | `/root/ankrshield/apps/xshieldai-hanumang/` | Unlicensed (internal) | Not distributed | (uses hanumang-mandate primitives internally) | SQLite persistence + Forja STATE/TRUST/SENSE/PROOF + signature crypto (Phase-2) + revocation polling |

**Two OSS HanumanGs is intentional** — they cover different governance moments:
- `@rocketlang/aegis` HanumanG → "Can this agent SPAWN?" (PreToolUse gate, binary)
- `@rocketlang/hanumang-mandate` → "Is this agent's MANDATE valid? What's its posture?" (continuous, graded)

When writing about HanumanG externally, name which one you mean. The README of `@rocketlang/hanumang-mandate` includes the comparison table that prevents confusion.

---

## 7. What competitors / forks can and cannot do

### Under AGPL-3.0 (OSS packages)

**Can:**
- Fork any `@rocketlang/*` package and run it forever, modified or unmodified.
- Build derivative products, *provided* network-service modifications are released under AGPL-3.0 (clause 13).
- Sell consulting / integration services.
- Embed in their own products if their products also ship under AGPL-3.0 (or they obtain a CLA-backed commercial dual-license).

**Cannot:**
- Run `@rocketlang/*` as a closed-source network service.
- Strip the AGPL-3.0 license and republish under a different license without CLA-backed permission.
- Use the AEGIS / KavachOS / HanumanG / PRAMANA / Mudrika / LakshmanRekha / Chitta trademarks for a derivative product without permission.

### Under BSL-1.1 (EE packages)

**Can:** read and modify source; use for internal business with ≤3 concurrent sessions free; non-production use; wait 4 years and use under AGPL-3.0.

**Cannot:** run as a production service with >3 concurrent agent sessions without commercial license; redistribute as competing managed service while still under BSL-1.1; strip the BSL-1.1 license.

---

## 8. The EE candidate pipeline — what is planned for BSL-1.1 EE

These are NOT in OSS today, are NOT yet built (or are partially built) in EE. Explicit BSL-1.1 EE candidates:

1. **PRAMANA Merkle ledger** — partially in `@rocketlang/kavachos-ee` v1.0.0
2. **HanumanG EE posture registry** — in `kavachos-ee` v1.0.0
3. **Dual-control approvals** — in `kavachos-ee` v1.0.0
4. **Maritime injection signatures** — in `kavachos-ee` v1.0.0
5. **Multi-tenant isolation** — in `kavachos-ee` v1.0.0
6. **Hosted attestation registry** as a service — TBD
7. **Multi-agent fleet dashboard** — TBD
8. **Replay simulation** — TBD
9. **Connectors** (Datadog / Splunk / PagerDuty / Slack-EE) — partially started
10. **SOC2 evidence packs** — TBD
11. **Cross-customer baselines** (anonymised pooled, with consent) — TBD
12. **chitta-guard hosted service** — internal today; EE candidate when externally desired (would consume `@rocketlang/chitta-detect`)
13. **xshieldai-asm-ai-module hosted service** — internal today; EE candidate (would consume `@rocketlang/lakshmanrekha`)
14. **xshieldai-hanumang hosted service** — internal today; EE candidate (would consume `@rocketlang/hanumang-mandate`)
15. **Mudrika signature crypto (Phase-2)** — required for hanumang-mandate over untrusted channels
16. **xshieldai-main, threat-intel feeds, honeypot engine** — explicitly listed in §2 closed table; NOT BSL-1.1 candidates; stay proprietary

When any of these gets built, the table in §2 is updated.

---

## 9. The discipline that keeps this honest

Three rules. If any of these slip, the open-core model loses its meaning.

1. **No EE-shaped feature accidentally lands in OSS.** Every PR that touches `@rocketlang/*` gets reviewed against §4 criteria. If unclear, default closed.
2. **No OSS-shaped primitive accidentally stays in EE.** Hiding primitives behind a BSL-1.1 paywall when they don't need to be is the failure mode that turned MongoDB into a non-open-core company. EE earns its keep through *operational leverage*, not by gatekeeping primitives.
3. **Trade secrets are off the table for both columns.** SLM internals, base weights, proprietary classifier architectures don't appear in either §2 sub-table.

---

## 10. Resolution path when this doc gets stale

This is v0.3. Every time we publish a new `@rocketlang/*` package, every time a feature moves between OSS and EE, every time the EE table grows: **this doc is updated in the same PR**. The boundary doc is not a snapshot; it is the running contract.

If this doc and reality ever diverge, **reality is wrong**, not the doc. The doc is the authoritative source.

### Version history

- **v0.1** (2026-05-16, morning) — greenfield-shaped; said EE was "commercial EULA"; assumed `@xshieldai` scope. Wrong on three counts. Replaced.
- **v0.2** (2026-05-16, afternoon) — reality-aligned after KAVACH triage. Captured 3 live packages + EE BSL-1.1 reality. §6 added for three-HanumanG situation.
- **v0.3** (2026-05-16, evening) — adds 4 packages shipped today: aegis-guard, chitta-detect, lakshmanrekha, hanumang-mandate. §6 updated: now FOUR HanumanG implementations (2 OSS, 1 EE, 1 internal). §2 grew. §8 EE pipeline gained the 3 internal-service-hosted-versions as natural future-EE candidates that would consume the new OSS primitives.

---

## 11. Related docs

- AEGIS README: `/root/aegis/README.md` (includes Fin Operator parity callout 2026-05-15)
- AEGIS DOI: 10.5281/zenodo.19625473
- PRAMANA DOI: 10.5281/zenodo.19273330
- CA-006 DOI (LakshmanRekha PROBE-001 source): 10.5281/zenodo.19508513
- xShieldAI capability overview: `/root/xshieldai-capability-overview-2026-05-16.txt`
- `[[feedback_slm_trade_secret]]` — SLM NULL principle
- `[[feedback_honesty_base_cybersecurity]]` — never inflate V
- `[[feedback_frugal_slm_strategy]]` — SLM is reasoning, RAG is knowledge, LoRA is adaptation
- Codex: `/root/aegis/codex.json` + per-package codex files (chitta-guard, xshieldai-* internal services)

---

*End of boundary doc v0.3. ~2,400 words. Lives at `/root/aegis/OPEN-CORE-BOUNDARY.md`. Updated 2026-05-16 evening after the 4-package campaign.*
