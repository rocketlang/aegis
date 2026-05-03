# Batch 31 Chirpee Soak Run 2/7
Date: 2026-05-02T23:17:49.573Z
Verdict: PASS
Total checks: 578 (PASS: 578, FAIL: 0)

## Metrics
- False positives: 0
- True positives: 10
- Invariant violations: 0
- Production gate fires: 0

## Traffic variation from run 1
- READ: 8 sessions × 6 ops = 48 decisions (was 30)
- Mixed-case caps: 9 variants tested (READ/Read/read/rEaD/GET/Get/get/LIST/List)
- WRITE: 8 sessions × 4 ops = 32 decisions (was 20)
- AI_EXECUTE: 5 sessions (was 3)
- Malformed: 10 (same targets — IMPOSSIBLE_OP × 5, EMPTY_CAPABILITY_ON_WRITE × 5)

## HG-1 justification (confirmed this run)
HG-1 does not hard-block risky real work.
HG-1 hard-blocks policy-proven impossible or malformed actions
that the soft gate intentionally does not interrupt.

  IMPOSSIBLE_OP             → soft=ALLOW, hard-sim=BLOCK (true positive)
  EMPTY_CAPABILITY_ON_WRITE → soft=ALLOW, hard-sim=BLOCK (true positive)

## Hard gate status
- HARD_GATE_GLOBALLY_ENABLED: false
- ready_to_promote_chirpee: false (2/7 runs complete)
