# Batch 36 — ship-slm + chief-slm HG-1 Live Hard-Gate Promotion

**Date:** 2026-05-03T01:22:46.681Z
**Verdict:** PASS

## Promotion

| Service | Rollout Order | Pre-Batch | Post-Batch |
|---------|--------------|-----------|------------|
| chirpee | 1 | LIVE | LIVE (unchanged) |
| ship-slm | 2 | soft-canary | **HG-1 LIVE** |
| chief-slm | 3 | soft-canary | **HG-1 LIVE** |

**AEGIS_HARD_GATE_SERVICES:** `chirpee,ship-slm,chief-slm`

## Evidence Chain

- Batch 34: policy prepared (hard_gate_enabled=false, simulation verified)
- Batch 35: 7/7 soak runs, 1403 total checks, 0 false positives
- Batch 35 verdict: promotion_permitted_ship_chief=true
- Batch 36: promotion executed (this script)

## Hard-Block Scope (unchanged)

Only 2 capabilities hard-BLOCK for ship-slm and chief-slm:
- `IMPOSSIBLE_OP` — demonstrably invalid sentinel
- `EMPTY_CAPABILITY_ON_WRITE` — empty capability on write-class op

## Rollback

Config-only. Remove `ship-slm,chief-slm` from `AEGIS_HARD_GATE_SERVICES`.
Both services immediately return to soft-canary. Chirpee remains independent.

## Checks

| Category | Checks | Result |
|----------|--------|--------|
| ship-slm live gate | 121 pass / 0 fail | PASS |
| chief-slm live gate | (included above) | |
| chirpee regression | (included above) | |
| puranic-os isolation | (included above) | |
| kill switch | (included above) | |
| rollback drill | PASS | |

**Total:** 121 checks, 121 PASS, 0 FAIL

## Next Stage

Stage 3: puranic-os HG-1 soak (Batch 37)
