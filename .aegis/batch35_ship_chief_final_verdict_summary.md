# Batch 35 — ship-slm + chief-slm HG-1 Soak 7/7 Final Verdict

**Date:** 2026-05-03T00:59:18.040Z
**Verdict:** PASS — 7/7 clean
**promotion_permitted_ship_chief:** true

## Soak run results

| Run | Focus | Result |
|---|---|---|
| 1/7 | Full surface (Run 1) | ✅ PASS |
| 2/7 | Mixed-case + alias normalization | ✅ PASS |
| 3/7 | Burst traffic + repeated malformed | ✅ PASS |
| 4/7 | Approval lifecycle heavy | ✅ PASS |
| 5/7 | Kill switch + rollback heavy | ✅ PASS |
| 6/7 | Unknown capability + boundary heavy | ✅ PASS |
| 7/7 | Final dress rehearsal | ✅ PASS |

## What was proven

- Normal work (READ/WRITE/domain ops) → not blocked ✅
- Malformed true positives → hard-sim BLOCK every time ✅
- Critical ops → soft GATE, hard-sim GATE (never BLOCK) ✅
- High ops (EXECUTE/APPROVE/SPAWN) → soft ALLOW, hard-sim ALLOW (still_gate does not upgrade) ✅
- Unknown caps → soft decision preserved, not hard-BLOCK ✅
- Unknown services → WARN, never BLOCK ✅
- Kill switch suppresses hard-gate overlay (AEG-E-006) ✅
- Rollback is config-only — immediate ✅
- chirpee live hard-gate unaffected throughout ✅

## Next step

**Batch 36**: Add ship-slm and chief-slm to AEGIS_HARD_GATE_SERVICES.
This is a manual act. hard_gate_enabled=false in the policy objects is NOT changed —
it remains the policy default. Only the env var changes.
