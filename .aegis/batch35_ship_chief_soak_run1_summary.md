# Batch 35 — ship-slm + chief-slm HG-1 Soak Run 1/7

**Date:** 2026-05-03T00:58:43.395Z
**Verdict:** PASS
**Soak progress:** 1/7 runs clean

## State going in

| Control | Value |
|---|---|
| HARD_GATE_GLOBALLY_ENABLED | true |
| AEGIS_HARD_GATE_SERVICES | chirpee only |
| ship-slm hard_gate_enabled | false (NOT LIVE) |
| chief-slm hard_gate_enabled | false (NOT LIVE) |
| Chirpee status | HG-1 live (Batch 32) |

## Soak results

| Metric | ship-slm | chief-slm | Combined |
|---|---|---|---|
| Decisions | 34 | 34 | 68 |
| True positives (sim BLOCK on malformed) | 8 | 8 | 16 |
| False positives (unexpected sim BLOCK) | 0 | 0 | 0 |
| Production gate fires | 0 | 0 | 0 |

## Invariants confirmed

| Invariant | Rule | Result |
|---|---|---|
| READ never hard-blocks | AEG-HG-002 | ✅ |
| still_gate does not upgrade ALLOW to GATE | — | ✅ |
| Production gate does not fire (sim(off)) | AEG-HG-001 | ✅ |
| Kill switch suppresses everything | AEG-E-006 | ✅ |
| Only chirpee in AEGIS_HARD_GATE_SERVICES | AEG-HG-003 | ✅ |
| Chirpee regression clean | — | ✅ |

## Checks: 423 total / 423 PASS / 0 FAIL

No failures.

## Soak schedule

| Run | Date | Verdict |
|---|---|---|
| 1/7 | 2026-05-03 | PASS |
| 2/7 | — | pending |
| 3/7 | — | pending |
| 4/7 | — | pending |
| 5/7 | — | pending |
| 6/7 | — | pending |
| 7/7 | — | pending |

**ready_to_promote_ship_chief = false** — requires 7/7 clean + human decision.

The first guard is armed. The next two are now on the range —
same weapon, same safety rules, but they still must pass their own watches.
