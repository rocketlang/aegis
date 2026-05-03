# Batch 37 — puranic-os HG-1 Soak Prep

**Date:** 2026-05-03T01:32:32.930Z
**Verdict:** PASS
**Stage:** Stage 3 prep — puranic-os NOT live

## Registry Profile (confirmed 2026-05-03)

| Field | Value |
|-------|-------|
| service_id | puranic-os |
| authority_class | read_only |
| governance_blast_radius | BR-1 |
| runtime_readiness.tier | TIER-A |
| rollout_order | 4 |
| hard_gate_enabled | false (prep only) |

**BR-1 vs BR-0:** puranic-os has slightly broader internal reach than chirpee/ship-slm/chief-slm.
Policy is identical. The 7-run soak validates false-positive surface under BR-1 before promotion.

## Simulation Results (dryRunOverride=true)

| Operation | Capability | Soft | Sim |
|-----------|-----------|------|-----|
| read | READ | ALLOW | ALLOW |
| get | GET | ALLOW | ALLOW |
| ai-execute | AI_EXECUTE | GATE | GATE |
| deploy | CI_DEPLOY | GATE | GATE |
| delete | DELETE | GATE | GATE |
| execute | EXECUTE | ALLOW | ALLOW (still_gate downgrade guard — not upgrade trigger) |
| frob | IMPOSSIBLE_OP | ALLOW | **BLOCK** ← true positive |
| write | EMPTY_CAPABILITY_ON_WRITE | ALLOW | **BLOCK** ← true positive |

## still_gate Semantics Verified

Downgrade guard only. If soft=ALLOW → sim preserves ALLOW (not GATE).
If soft=BLOCK → sim returns GATE (downgrade, not hard BLOCK).

## Operation/Capability Alignment

- `op="execute"` → risk=high → ALLOW (read_only + BR-1)
- `op="ai-execute"` → risk=critical → GATE
- Alias normalization is correct; operation must match intended risk tier in tests.

## Live HG-1 Regression

All 3 live services unaffected: chirpee, ship-slm, chief-slm → BLOCK on IMPOSSIBLE_OP.

## Kill Switch

All 3 live services + puranic-os → shadow under AEGIS_RUNTIME_ENABLED=false.
Restore: chirpee/ship-slm/chief-slm back to hard_gate; puranic-os back to soft_canary.

## Checks

| Category | Result |
|----------|--------|
| Pre-flight | PASS |
| Normal read/write | PASS |
| Critical op alignment | PASS |
| Malformed TPs | 2 TPs (IMPOSSIBLE + EMPTY) |
| still_gate semantics | PASS |
| Unknown cap guard | PASS |
| Live HG-1 regression | PASS |
| Kill switch | PASS |
| **Total** | **118 checks, 118 PASS, 0 FAIL** |

## Next: Stage 3 Soak (Batch 38 → Batch 39)

Policy is ready. Proceed with 7-run soak for puranic-os.
- Run 1: baseline coverage (Batch 38)
- Runs 2–7: varied stress patterns
- Promotion: Batch 40 (after 7/7 PASS)

Three guards are now live. The fourth has BR-1, not BR-0 —
close enough to train, not close enough to skip the watches.
