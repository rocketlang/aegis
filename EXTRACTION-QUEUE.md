# OSS Extraction Queue

**Status:** v1.0 — seeded 2026-05-16 evening alongside `OPEN-CORE-BOUNDARY.md` v0.5 + `STRATEGY.md` v1.0.
**Purpose:** running list of `@rocketlang/*` OSS extraction candidates from the 500+ Verdaccio + 200+ services. Updated as items move through queue.
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
| 1 | `@rocketlang/pramana-receipts` | `/root/aegis/ee/kavach/pramana-receipts.ts` (currently BSL-1.1) | S | queued | Moves from EE → OSS. Completes the OSS PRAMANA proof loop (the OSS Merkle ledger is already there; receipts were the missing producer). 165 lines. DOI 10.5281/zenodo.19273330. |
| 2 | `@rocketlang/dual-control` | `/root/aegis/ee/kavach/*` (currently BSL-1.1) | S | queued | Two-key approval primitive. Pure logic; no infra. |
| 3 | `@rocketlang/hanumang-registry` | `/root/aegis/ee/shield/hanumang-ee.ts` (currently BSL-1.1) | S | queued | Domain registry + GREEN/AMBER/RED scoring. The "registry" sub-primitive that complements the OSS spawn-check + mandate scorer. |
| 4 | `@rocketlang/maritime-injection-signatures` | `/root/aegis/ee/shield/maritime-signatures.ts` (currently BSL-1.1) | S | queued | Pattern data for maritime OT injection signatures. Same shape as lakshmanrekha PROBE_REGISTRY but for vessel protocols. |
| 5 | `@rocketlang/slack-notifier` | `/root/aegis/ee/kavach/slack-notifier.ts` (currently BSL-1.1) | S | queued | Alternative: merge into `@rocketlang/aegis` rather than separate package. Decide at audit time. |
| 6 | `@rocketlang/session-oracle` | `/root/aegis/src/oracle/` (currently inside aegis OSS but un-broken-out) | M | queued | brief.ts + probe.ts + spawn-gate.ts. Session-start health brief generator. Already runs in aegis; extract as standalone primitive so other services can use it. |
| 7 | `@rocketlang/machine-law` | `/root/aegis/src/machine-law/` (currently inside aegis OSS) | M | queued | lawful-action-map.ts + policy-hash.ts (aegis-shastra MVP). Same shape — extract from aegis to standalone primitive. |
| 8 | `@rocketlang/genetic-trust` | `/root/aegis/src/kavach/genetic-trust.ts` (currently inside kavachos OSS) | S | queued | GNT-001 + GNT-002 trust mask inheritance primitive. Single-file extraction. |
| 9 | `@rocketlang/sdge` | `ankr-sovereign-doc.ts` (referenced by merkle-ledger.ts) | M | triage | Sovereign Document signing pattern reused by Merkle STH. Needs audit to find the actual source file + assess scope. |
| 10 | `@rocketlang/bitmask-os` | `/root/apps/bitmaskos/` | M-L | triage | Per-process bitmask OS layer. Phases 1, 3, 5 done (spawn gate, TTL inheritance, spawn_chain_enforced). Needs audit to classify Group A vs B. Could be substantial. |
| 11 | `@rocketlang/scope-mandate` (or hanumang-mandate v0.2 axes) | new code — design choice at extraction time | M | queued | Addresses "scope discovery" failure surfaced by Foley's CNCF Kubernetes benchmark (2026-05-15). Three candidate axes: `scope_completeness` (agent enumerated all touched files/functions/tests + named what it considered AND rejected as out-of-scope), `dependency_propagation` (agent identified downstream consumers and either updated or explicitly deferred), `reuse_first` (agent searched for existing abstractions before introducing new ones — counters the "new Attempt field vs existing RestartCount" failure). **Design choice at extraction time:** new sibling package OR hanumang-mandate v0.2 added axes. My lean: sibling package — current 7 axes are about *behaving correctly during the action*; scope is about *recognising the action's extent*. Different concern, different package. |

---

## Phase-2 work on shipped packages

Not new packages, but follow-up work on the 4 packages shipped today:

| Package | Phase-2 work | Effort | Priority |
|---|---|---|---|
| `@rocketlang/aegis-guard` | Test suite (v0.1.1) | S | mid |
| `@rocketlang/chitta-detect` | Test suite (v0.1.1) | S | mid |
| `@rocketlang/lakshmanrekha` | Test suite + async runner (v0.2) | M | mid |
| `@rocketlang/hanumang-mandate` | Test suite + signature crypto (v0.2) | M | high — signature crypto unblocks untrusted-channel use |
| `@rocketlang/aegis` | v2.2.0 publish for README Fin parity callout to show on npmjs.com | S | low — already on GitHub |
| `@rocketlang/aegis` | LICENSE wording cleanup (current LICENSE has "Commercial use requires separate license" clause technically incompatible with pure AGPL-3.0) | S | low — non-blocking; clarify dual-licensing language |

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
| chitta-guard | `/root/chitta-guard/` | Primitive shipped as `@rocketlang/chitta-detect`. Shell stays internal. ✅ done. |
| xshieldai-asm-ai-module | `/root/ankrshield/apps/xshieldai-asm-ai-module/` | Primitive shipped as `@rocketlang/lakshmanrekha`. ✅ done. |
| xshieldai-hanumang | `/root/ankrshield/apps/xshieldai-hanumang/` | Primitive shipped as `@rocketlang/hanumang-mandate`. ✅ done. |
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
