# Batch 33 — Chirpee HG-1 Live Observation Window

**Date:** 2026-05-03T00:29:37.908Z
**Verdict:** PASS
**Batch:** 33 — Post-promotion hard-gate observation

## State going in

| Control | Value |
|---|---|
| HARD_GATE_GLOBALLY_ENABLED | true (Batch 32) |
| AEGIS_HARD_GATE_SERVICES | chirpee |
| chirpee stage | Stage 1 — HG-1 pilot — LIVE |
| Hard-block capabilities | IMPOSSIBLE_OP, EMPTY_CAPABILITY_ON_WRITE |

## Results

| Category | Decisions | Hard BLOCKs | Result |
|---|---|---|---|
| Normal traffic (READ/WRITE/ROUTE) | 11 | 0 | ✅ |
| High-risk real actions (GATE) | 8 | 0 | ✅ |
| Malformed true positives (BLOCK) | 16 | 16 | ✅ |
| Unknown service (WARN) | 6 | 0 | ✅ |
| Non-promoted TIER-A services | 3 | 0 | ✅ |
| Unknown capability (GATE/WARN) | 5 | 0 | ✅ |
| Kill switch (shadow) | 3 | 1 | ✅ |
| **Total** | **52** | **17** | **PASS** |

## Invariant confirmation

| Invariant | Rule | Status |
|---|---|---|
| READ never blocks | AEG-HG-002 | ✅ confirmed |
| Unknown service → WARN | AEG-E-007 | ✅ confirmed |
| Unknown cap → GATE/WARN | AEG-HG-003 | ✅ confirmed |
| High-risk → GATE not BLOCK | AEG-HG-001 | ✅ confirmed |
| Kill switch beats hard-gate | AEG-E-006 | ✅ confirmed |
| Only chirpee promoted | AEG-HG-003 | ✅ ship-slm/chief-slm unchanged |
| Rollback is config-only | — | ✅ confirmed |

## Checks

- Total: 186
- Pass: 186
- Fail: 0

No failures.

## Stage 2 readiness

Batch 33 PASS. Observation window confirms the activated state is stable under traffic.
Ship-slm + chief-slm HG-1 soak (Batch 34) may now proceed.
