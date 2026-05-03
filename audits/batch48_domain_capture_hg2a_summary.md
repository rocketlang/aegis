# Batch 48 — domain-capture HG-2A Live Hard-Gate Promotion

Date: 2026-05-03T06:22:57.785Z
Verdict: **PASS**
Checks: 148  Pass: 148  Fail: 0  Production fires: 0

## Pre-Check

Batch 47 verdict: 7/7 soak PASS · 472 total checks · 0 false positives · 0 production fires
`promotion_permitted_domain_capture=true`
Promotion authorized.

## Live Status

| Service | HG Group | Phase | Hard-Gate Enabled | Since |
|---------|----------|-------|------------------|-------|
| chirpee | HG-1 | hard_gate (live) | true | Batch 32 |
| ship-slm | HG-1 | hard_gate (live) | true | Batch 36 |
| chief-slm | HG-1 | hard_gate (live) | true | Batch 36 |
| puranic-os | HG-1 | hard_gate (live) | true | Batch 39 |
| pramana | HG-2A | hard_gate (live) | true | Batch 43 |
| **domain-capture** | **HG-2A** | **hard_gate (LIVE — Batch 48)** | **true** | **Batch 48** |

## Isolated (not promoted)

| Service | Status |
|---------|--------|
| parali-central | HG-2B — external impact review pending |
| carbonx | HG-2B — external impact review pending |
| ankr-doctor | HG-2C — separate governance review |

## domain-capture Hard-Gate Surface

**BLOCK:** IMPOSSIBLE_OP, EMPTY_CAPABILITY_ON_WRITE
**GATE:** EXECUTE, CI_DEPLOY, DELETE, APPROVE, AI_EXECUTE, EMIT
**ALLOW:** READ, GET, LIST, QUERY, SEARCH, HEALTH (+ domain ops: CAPTURE_DOMAIN, CLASSIFY_DOMAIN, EXTRACT_RULES, INDEX_DOMAIN, AUDIT_DOMAIN, ANALYZE_PATTERN)
**still_gate (downgrade guard):** MEMORY_WRITE, AUDIT_WRITE, SPAWN_AGENTS, TRIGGER, FULL_AUTONOMY
  - soft BLOCK → hard GATE (never live-BLOCK these caps)
  - soft ALLOW → remains ALLOW (not soft-gated; tested via simulateHardGate)

## Approval Lifecycle — Hard-Gate Phase (NEW in Batch 48)

**Soak phase (soft_canary):** approval_token present for audit; approveToken/denyToken/revokeToken methods absent.
**Hard-gate phase (this batch):** approval_token present; full approve/deny/revoke lifecycle LIVE.

Verified:
- approveToken(token, msg, actor) → ok=true (first call)
- approveToken replay → ok=false (token consumed — idempotent rejection)
- denyToken(token, msg, actor) → ok=true (denial recorded)
- revokeToken(token, msg, actor) → ok=true (revocation recorded)
- token uniqueness: 3 distinct GATE decisions → 3 distinct tokens

## Rollback

AEGIS_HARD_GATE_SERVICES is the runtime switch.
Remove domain-capture from it → immediate return to soft_canary. No code change needed.
pramana and HG-1 services remain stable during domain-capture rollback.
Kill switch suppresses all 6 live services simultaneously.

## Soak Reference

Batch 46: run 1 — 123 checks, 0 FP, 0 prod fires
Batch 47: runs 2–7 — 349 checks, 0 FP, 0 prod fires
Total soak: 472 checks, 7/7 PASS
batch47_domain_capture_final_verdict.json: promotion_permitted_domain_capture=true

## Standing Doctrine — still_gate gotcha

MEMORY_WRITE / AUDIT_WRITE / SPAWN_AGENTS are downgrade-guard caps only.
The soft layer returns ALLOW for them. still_gate only fires when soft=BLOCK.
NOT guaranteed soft-gated through evaluate() — test via simulateHardGate().
Locked: Batch 42 Run 7/7. Confirmed for domain-capture: Batch 48.
