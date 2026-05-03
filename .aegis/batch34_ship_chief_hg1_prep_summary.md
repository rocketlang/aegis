# Batch 34 — ship-slm + chief-slm HG-1 Soak Prep

**Date:** 2026-05-03T00:37:35.288Z
**Verdict:** PASS
**Batch:** 34 — Stage 2 HG-1 prep (policies added, not live)

## State going in

| Control | Value |
|---|---|
| HARD_GATE_GLOBALLY_ENABLED | true |
| AEGIS_HARD_GATE_SERVICES | chirpee only |
| ship-slm hard_gate_enabled | false (NOT LIVE) |
| chief-slm hard_gate_enabled | false (NOT LIVE) |

## Registry pre-check

| Service | Tier | authority_class | BR | HG-1 eligible |
|---|---|---|---|---|
| ship-slm | TIER-A | read_only | BR-0 | ✅ |
| chief-slm | TIER-A | read_only | BR-0 | ✅ |

## Simulation results

| Category | ship-slm | chief-slm |
|---|---|---|
| READ/GET/LIST → ALLOW | ✅ | ✅ |
| WRITE → not BLOCK | ✅ | ✅ |
| IMPOSSIBLE_OP → sim BLOCK | ✅ | ✅ |
| EMPTY_CAPABILITY_ON_WRITE → sim BLOCK | ✅ | ✅ |
| Critical ops → not BLOCK | ✅ | ✅ |
| still_gate: zero ALLOW→GATE upgrades | ✅ | ✅ |
| Unknown cap → not hard-BLOCK | ✅ | ✅ |

## Chirpee regression

| Check | Result |
|---|---|
| IMPOSSIBLE_OP still live BLOCK | ✅ |
| READ still ALLOW | ✅ |
| Kill switch still suppresses hard-gate | ✅ |

## Checks

- Total: 123
- Pass: 123
- Fail: 0

No failures.

## Still-gate semantics verified

still_gate is a downgrade guard only (BLOCK→GATE).
It never upgrades ALLOW to GATE.
Violations in simulation matrix: 0 (must be 0).

## Next step

Batch 34 PASS. Policies are correctly calibrated.
Batch 35 may now begin: ship-slm + chief-slm HG-1 soak run 1/7.
Do NOT add either service to AEGIS_HARD_GATE_SERVICES yet.
