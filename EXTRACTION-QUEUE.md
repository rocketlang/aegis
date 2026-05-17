# OSS Extraction Queue

**Status:** v1.2 — updated 2026-05-17 late evening after brand consolidation wave. All packages now under `@xshieldai/*` (npm) and `xshieldai-*` (PyPI). Old packages under `@` + `rocketlang` + `/*` are deprecated on npm. Phase-2 v0.2.0 work shipped under new names. See `MIGRATION.md`.
**Purpose:** running list of `@xshieldai/*` OSS extraction candidates from the 500+ Verdaccio + 200+ services. Updated as items move through queue.
**Pace target:** 1-2 packages per week sustained (per `STRATEGY.md`).

---

## How the queue works

### Triage groups

Every candidate package falls in one of four groups (per `STRATEGY.md`):

- **Group A** — Primitive, OSS-shape, ready to extract. The publish-worthy bucket. (~30% of the 500+, ~150 packages over 2-3 years.)
- **Group B** — Application / service, not OSS-shape. Consume primitives, are themselves the moat. Stay private. (~40%, ~200 packages.)
- **Group C** — Trade-secret-adjacent. SLM internals, classified IP. **Never OSS, never EE.** (~10%, ~50 packages.)
- **Group D** — Legacy / dead / experimental. Don't ship anywhere. Periodic Verdaccio cleanup. (~20%, ~100 packages.)

Only Group A enters this queue.

### Effort sizing

- **S** — small (1-2 days from audit to publish, same pattern as today's chitta-detect / lakshmanrekha / hanumang-mandate)
- **M** — medium (3-7 days — needs refactor before primitives are extractable)
- **L** — large (1-2 weeks — substantial reshape or new tests required)

### Status

- `queued` — identified, not started
- `triage` — audit in progress (purity check, dep analysis, OSS/EE classification)
- `building` — extraction in progress
- `shipped` — published to npm, boundary doc updated, commit pushed
- `deferred` — audit revealed bigger work than initial estimate; back to queue with new sizing
- `dropped` — audit revealed it shouldn't be OSS after all (often moves to Group B/C/D)

---

## Active queue (top candidates as of 2026-05-16)

The following 10 are the seed list. Each is grounded in code seen this session; each follows the same extraction discipline today's 4 publishes used.

| # | Candidate package | Source | Effort | Status | Notes |
|---|---|---|---|---|---|
| 1 | `@xshieldai/pramana-receipts` | `/root/aegis/ee/kavach/pramana-receipts.ts` (currently BSL-1.1) | S | queued | Moves from EE → OSS. Completes the OSS PRAMANA proof loop (the OSS Merkle ledger is already there; receipts were the missing producer). 165 lines. DOI 10.5281/zenodo.19273330. |
| 2 | `@xshieldai/dual-control` | `/root/aegis/ee/kavach/*` (currently BSL-1.1) | S | queued | Two-key approval primitive. Pure logic; no infra. |
| 3 | `@xshieldai/hanumang-registry` | `/root/aegis/ee/shield/hanumang-ee.ts` (currently BSL-1.1) | S | queued | Domain registry + GREEN/AMBER/RED scoring. The "registry" sub-primitive that complements the OSS spawn-check + mandate scorer. |
| 4 | `@xshieldai/maritime-injection-signatures` | `/root/aegis/ee/shield/maritime-signatures.ts` (currently BSL-1.1) | S | queued | Pattern data for maritime OT injection signatures. Same shape as lakshmanrekha PROBE_REGISTRY but for vessel protocols. |
| 5 | `@xshieldai/slack-notifier` | `/root/aegis/ee/kavach/slack-notifier.ts` (currently BSL-1.1) | S | queued | Alternative: merge into `@xshieldai/aegis` rather than separate package. Decide at audit time. |
| 6 | `@xshieldai/session-oracle` | `/root/aegis/src/oracle/` (currently inside aegis OSS but un-broken-out) | M | queued | brief.ts + probe.ts + spawn-gate.ts. Session-start health brief generator. Already runs in aegis; extract as standalone primitive so other services can use it. |
| 7 | `@xshieldai/machine-law` | `/root/aegis/src/machine-law/` (currently inside aegis OSS) | M | queued | lawful-action-map.ts + policy-hash.ts (aegis-shastra MVP). Same shape — extract from aegis to standalone primitive. |
| 8 | `@xshieldai/genetic-trust` | `/root/aegis/src/kavach/genetic-trust.ts` (currently inside kavachos OSS) | S | queued | GNT-001 + GNT-002 trust mask inheritance primitive. Single-file extraction. |
| 9 | `@xshieldai/sdge` | `ankr-sovereign-doc.ts` (referenced by merkle-ledger.ts) | M | triage | Sovereign Document signing pattern reused by Merkle STH. Needs audit to find the actual source file + assess scope. |
| 10 | `@xshieldai/bitmask-os` | `/root/apps/bitmaskos/` | M-L | triage | Per-process bitmask OS layer. Phases 1, 3, 5 done (spawn gate, TTL inheritance, spawn_chain_enforced). Needs audit to classify Group A vs B. Could be substantial. |
| 11 | `@xshieldai/scope-mandate` (or hanumang-mandate v0.2 axes) | new code — design choice at extraction time | M | queued | Addresses "scope discovery" failure surfaced by Foley's CNCF Kubernetes benchmark (2026-05-15). Three candidate axes: `scope_completeness` (agent enumerated all touched files/functions/tests + named what it considered AND rejected as out-of-scope), `dependency_propagation` (agent identified downstream consumers and either updated or explicitly deferred), `reuse_first` (agent searched for existing abstractions before introducing new ones — counters the "new Attempt field vs existing RestartCount" failure). **Design choice at extraction time:** new sibling package OR hanumang-mandate v0.2 added axes. My lean: sibling package — current 7 axes are about *behaving correctly during the action*; scope is about *recognising the action's extent*. Different concern, different package. |

---

## Phase-2 work on shipped packages

Status snapshot after Day 5 of the ACC wave (2026-05-17):

| Package | Phase-2 work | Effort | Status |
|---|---|---|---|
| `@xshieldai/aegis-guard` | v0.2.0 opt-in `setEventBus()` for ACC | S | **shipped 2026-05-16 — v0.2.0 on npm** |
| `@xshieldai/chitta-detect` | v0.2.0 opt-in `setEventBus()` for ACC | S | **shipped 2026-05-16 — v0.2.0 on npm** |
| `@xshieldai/lakshmanrekha` | v0.2.0 opt-in `setEventBus()` for ACC | S | **shipped 2026-05-16 — v0.2.0 on npm** (async runner still pending v0.3) |
| `@xshieldai/hanumang-mandate` | v0.2.0 opt-in `setEventBus()` for ACC | S | **shipped 2026-05-16 — v0.2.0 on npm** (signature crypto still pending v0.3 — unblocks untrusted-channel use) |
| `@xshieldai/aegis-suite` | v0.2.0 `wireAllToBus()` helper + self-contained bus + SqliteEventWriter | S | **shipped 2026-05-17 — v0.2.0 on npm** |
| `@xshieldai/aegis` | v2.2.0 with Agentic Control Center (`/control-center`, `/agent/:id`, `/suite`, SSE, AOS panels, EE-aware PRAMANA panel) + README Fin parity callout | M | **shipped 2026-05-17 — v2.2.0 on npm** |
| `@xshieldai/aegis-guard` | Test suite (independent v0.2.1) | S | queued — mid priority |
| `@xshieldai/chitta-detect` | Test suite (independent v0.2.1) | S | queued — mid priority |
| `@xshieldai/lakshmanrekha` | Test suite + async runner (v0.3) | M | queued — mid priority |
| `@xshieldai/hanumang-mandate` | Test suite + signature crypto (v0.3) | M | queued — high priority (signature crypto unblocks untrusted-channel use) |
| `@xshieldai/aegis-suite` | Smoke tests for `wireAllToBus()` end-to-end + filter UI for `/control-center` | S-M | queued — to land with aegis v2.3.0 |
| `@xshieldai/aegis` | LICENSE wording cleanup (current LICENSE has "Commercial use requires separate license" clause technically incompatible with pure AGPL-3.0) | S | queued — low priority; non-blocking; clarify dual-licensing language |

---

## Broader Verdaccio survey — TBD

The 500+ packages in `swayam.digimitra.guru/npm` need a systematic triage to identify additional Group A candidates beyond the 10 above. **Not done in this seed pass.** Approach when ready:

1. Pull list of all `@ankr/*` packages from Verdaccio
2. For each, classify Group A/B/C/D (purity audit + dep check)
3. Group A candidates added to this queue with effort estimate
4. Group D candidates flagged for cleanup
5. Output: a CSV / JSON inventory at `/root/aegis/internal-package-inventory.json` (gitignored, internal-only — contains Verdaccio listing)

**Estimated effort to triage 500 packages: ~3-4 days.** Defer until current 10 candidates flow through. No point queueing 100 candidates if pace is 1-2/week.

---

## Service-level extraction TBD

The 200+ services across `/root/ankrshield/apps/`, `/root/apps/`, `/root/ankr-labs-nx/apps/`, etc. typically:
- Have a primitive layer (extractable as OSS)
- Have a service shell (Fastify routes + DB + integration — stays internal/EE)
- Have a CLI / UI (depends on shell — stays with shell)

For each service: same audit pattern as chitta-guard → chitta-detect today. Extract the primitive; leave the shell.

**Estimated effort per service: 1-3 days from audit to publish** (same as today's pattern).

Candidate services to audit (not all OSS-extractable; this is the audit candidate list):

| Service | Path | Current state |
|---|---|---|
| chitta-guard | `/root/chitta-guard/` | Primitive shipped as `@xshieldai/chitta-detect`. Shell stays internal. ✅ done. |
| xshieldai-asm-ai-module | `/root/ankrshield/apps/xshieldai-asm-ai-module/` | Primitive shipped as `@xshieldai/lakshmanrekha`. ✅ done. |
| xshieldai-hanumang | `/root/ankrshield/apps/xshieldai-hanumang/` | Primitive shipped as `@xshieldai/hanumang-mandate`. ✅ done. |
| xshieldai-kavach | (registered but no source dir) | Spec only, no extraction needed. |
| xshieldai-varuna | `/root/ankrshield/apps/xshieldai-varuna/` | Pre-build; revisit when service ships. |
| (200+ more) | various | Not yet triaged |

---

## How this doc gets maintained

Same discipline as `OPEN-CORE-BOUNDARY.md`:

- Every extraction starts with a row added here (`status: queued` → `triage` → `building` → `shipped`).
- Every shipped row updates the boundary doc §2 LIVE-on-npm table same-PR.
- Periodic cleanup (~monthly): drop `shipped` rows older than 30 days; archive `dropped` rows with reason.
- New candidates surface as audits reveal them; not all queue additions come from this seed list.

---

## Resolution path

This is v1.0. Updates land in same PR as either:
- a boundary doc v0.X bump (when extraction reshapes the boundary)
- a new package publish (when an item moves from `building` → `shipped`)
- a periodic queue grooming (drop stale rows, add new candidates)

Like the boundary doc, this is the running contract. If queue and reality diverge, reality is wrong.

---

*Companion docs: `OPEN-CORE-BOUNDARY.md` (the what) · `STRATEGY.md` (the why).*
