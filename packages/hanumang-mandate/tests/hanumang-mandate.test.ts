// @xshieldai/hanumang-mandate — v0.2.1 unit test suite
// ~38 tests across §1-§4 covering verifyMudrika (structural + TTL + agent-id
// + range) + 7-axis scoreAxis + computePostureScore (incl. HNG-YK-001
// worst-axis-floor invariant) + ACC bus emission.
//
// PHASE-1 LIMIT explicitly tested: verifyMudrika does NOT crypto-verify the
// signature field. Tests document this as observable behavior (a structurally
// valid mudrika with an invalid signature PASSES today; this is intentional
// for v0.2.1 and a regression target for v0.3 when signature crypto lands).

import { describe, it, expect, beforeEach } from 'bun:test';
import {
  verifyMudrika,
  scoreAxis,
  computePostureScore,
  setEventBus,
  isBusWired,
  type MudrikaPayload,
  type AccReceipt,
  type AxisInput,
  type AxisScore,
} from '../src/index.js';

function validMudrika(over: Partial<MudrikaPayload> = {}): MudrikaPayload {
  return {
    mudrika_version: 'v1',
    mudrika_id: `mdr-test-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
    principal_id: 'user:capt-anil',
    agent_id: 'agent:codex-001',
    task_id: 'task:refactor',
    trust_mask: 0b00011111,
    scope_key: 'aegis/packages/aegis-guard',
    issued_at: new Date().toISOString(),
    ttl_seconds: 3600,
    required_return_proof: 'pramana_receipt',
    revocation_url: 'https://aegis.example.com/mudrika/revoke',
    pramana_chain: ['root', 'pramana:abc123'],
    ...over,
  };
}

// ─── §1 verifyMudrika (HNG-S-008 / HNG-S-009 / HNG-S-010) ─────────────────────

describe('§1 verifyMudrika — structural + TTL + range', () => {
  beforeEach(() => setEventBus(null));

  it('HM-001: valid mudrika → PASS, expires_at populated', () => {
    const m = validMudrika();
    const r = verifyMudrika(m, m.agent_id);
    expect(r.outcome).toBe('PASS');
    expect(r.failure_reason).toBeNull();
    expect(r.trust_mask).toBe(0b00011111);
    expect(r.scope_key).toBe('aegis/packages/aegis-guard');
    expect(r.principal_id).toBe('user:capt-anil');
    expect(r.mudrika_id).toBe(m.mudrika_id);
    expect(r.pramana_chain).toEqual(['root', 'pramana:abc123']);
    expect(r.expires_at).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(r.duration_ms).toBeGreaterThanOrEqual(0);
  });

  it('HM-002: null/undefined input → FAIL mudrika_missing', () => {
    const r = verifyMudrika(null);
    expect(r.outcome).toBe('FAIL');
    expect(r.failure_reason).toBe('mudrika_missing');
  });

  it('HM-003: non-object input → FAIL mudrika_missing', () => {
    expect(verifyMudrika('a string').outcome).toBe('FAIL');
    expect(verifyMudrika(42).outcome).toBe('FAIL');
  });

  it('HM-004: missing required fields → FAIL', () => {
    const r = verifyMudrika({ mudrika_id: 'abc' });
    expect(r.outcome).toBe('FAIL');
    expect(r.failure_reason).toBe('missing_required_fields');
  });

  it('HM-005: agent_id mismatch when expected provided → FAIL', () => {
    const m = validMudrika({ agent_id: 'agent:wrong' });
    const r = verifyMudrika(m, 'agent:expected');
    expect(r.outcome).toBe('FAIL');
    expect(r.failure_reason).toContain('agent_id_mismatch');
  });

  it('HM-006: agent_id check skipped when no expected provided', () => {
    const m = validMudrika({ agent_id: 'agent:whatever' });
    const r = verifyMudrika(m);  // no expected_agent_id
    expect(r.outcome).toBe('PASS');
  });

  it('HM-007: TTL already expired → EXPIRED outcome (HNG-S-009)', () => {
    const m = validMudrika({
      issued_at: new Date(Date.now() - 7200 * 1000).toISOString(),
      ttl_seconds: 3600,  // expired 1 hour ago
    });
    const r = verifyMudrika(m, m.agent_id);
    expect(r.outcome).toBe('EXPIRED');
    expect(r.failure_reason).toContain('expired');
  });

  it('HM-008: invalid issued_at → FAIL', () => {
    const m = validMudrika({ issued_at: 'not-a-date' });
    const r = verifyMudrika(m, m.agent_id);
    expect(r.outcome).toBe('FAIL');
    expect(r.failure_reason).toBe('invalid_issued_at');
  });

  it('HM-009: trust_mask in 32-bit range accepted', () => {
    expect(verifyMudrika(validMudrika({ trust_mask: 0 })).outcome).toBe('PASS');
    expect(verifyMudrika(validMudrika({ trust_mask: 0xffffffff })).outcome).toBe('PASS');
  });

  it('HM-010: trust_mask out of 32-bit range → FAIL', () => {
    const r = verifyMudrika(validMudrika({ trust_mask: 0x1_0000_0000 }));
    expect(r.outcome).toBe('FAIL');
    expect(r.failure_reason).toBe('trust_mask_out_of_range');
  });

  it('HM-011: PHASE-1 LIMIT — invalid signature does NOT cause failure (crypto not yet implemented)', () => {
    // This is the documented Phase-1 limit: signature is NOT cryptographically
    // verified. A mudrika with a bogus signature still PASSES if structure + TTL
    // + trust_mask range are valid. Phase-2 (v0.3) will add real signature
    // verification — when it does, this test must FLIP to expect FAIL.
    const m = validMudrika({ signature: 'completely-fake-signature-not-checked' });
    const r = verifyMudrika(m, m.agent_id);
    expect(r.outcome).toBe('PASS');  // FLIP to FAIL in v0.3 when crypto lands
  });

  it('HM-012: pramana_chain defaults to [] when absent', () => {
    const m = validMudrika();
    delete (m as any).pramana_chain;
    const r = verifyMudrika(m, m.agent_id);
    expect(r.pramana_chain).toEqual([]);
  });
});

// ─── §2 scoreAxis (HNG-S-001 .. HNG-S-007) ────────────────────────────────────

describe('§2 scoreAxis — 7 axes', () => {
  beforeEach(() => setEventBus(null));

  // Axis 1: mudrika_integrity
  it('HM-013: mudrika_integrity all good → 100 PASS', () => {
    const r = scoreAxis({
      axis: 'mudrika_integrity',
      mudrika_verified: true,
      mudrika_ttl_remaining_s: 600,
      pramana_chain_depth: 2,
    });
    expect(r.score).toBe(100);
    expect(r.outcome).toBe('PASS');
    expect(r.rule_id).toBe('HNG-S-001');
  });

  it('HM-014: mudrika_integrity not verified → 0 FAIL', () => {
    const r = scoreAxis({ axis: 'mudrika_integrity', mudrika_verified: false });
    expect(r.score).toBe(0);
    expect(r.outcome).toBe('FAIL');
    expect(r.notes[0]).toContain('mudrika absent');
  });

  it('HM-015: mudrika_integrity expiring soon → 80 PASS', () => {
    const r = scoreAxis({
      axis: 'mudrika_integrity',
      mudrika_verified: true,
      mudrika_ttl_remaining_s: 10,  // <30s
      pramana_chain_depth: 1,
    });
    expect(r.score).toBe(80);
    expect(r.outcome).toBe('PASS');
  });

  // Axis 2: identity_broadcast
  it('HM-016: identity_broadcast — all 6 required fields → 100 PASS', () => {
    const r = scoreAxis({
      axis: 'identity_broadcast',
      self_declared: true,
      declared_fields: ['agentId', 'agentType', 'officerRole', 'scopeKey', 'taskId', 'delegatedBy'],
    });
    expect(r.score).toBe(100);
    expect(r.outcome).toBe('PASS');
  });

  it('HM-017: identity_broadcast — not self-declared → 0 FAIL', () => {
    const r = scoreAxis({ axis: 'identity_broadcast', self_declared: false });
    expect(r.score).toBe(0);
    expect(r.outcome).toBe('FAIL');
  });

  it('HM-018: identity_broadcast — missing 3 fields → 70 WARN', () => {
    const r = scoreAxis({
      axis: 'identity_broadcast',
      self_declared: true,
      declared_fields: ['agentId', 'agentType', 'officerRole'],  // missing 3
    });
    expect(r.score).toBe(70);
    expect(r.outcome).toBe('WARN');
  });

  // Axis 3: mandate_bounds
  it('HM-019: mandate_bounds — child mask ⊆ parent → 100 PASS', () => {
    const r = scoreAxis({
      axis: 'mandate_bounds',
      trust_mask_granted: 0b11111,
      trust_mask_requested: 0b01111,
      scope_key_match: true,
      ttl_respected: true,
    });
    expect(r.score).toBe(100);
    expect(r.outcome).toBe('PASS');
  });

  it('HM-020: mandate_bounds — child requests bits parent does not have → 0 FAIL (spawn invariant)', () => {
    const r = scoreAxis({
      axis: 'mandate_bounds',
      trust_mask_granted: 0b00001,
      trust_mask_requested: 0b11111,  // requests bits 1-4 parent doesn't have
      scope_key_match: true,
      ttl_respected: true,
    });
    expect(r.score).toBe(0);
    expect(r.outcome).toBe('FAIL');
    expect(r.notes[0]).toContain('exceeds');
  });

  it('HM-021: mandate_bounds — scope_key_match=false → 0 FAIL', () => {
    const r = scoreAxis({
      axis: 'mandate_bounds',
      trust_mask_granted: 0b1,
      trust_mask_requested: 0b1,
      scope_key_match: false,
    });
    expect(r.score).toBe(0);
    expect(r.outcome).toBe('FAIL');
  });

  it('HM-022: mandate_bounds — ttl_respected=false → -40 (60 WARN)', () => {
    const r = scoreAxis({
      axis: 'mandate_bounds',
      trust_mask_granted: 0b1,
      trust_mask_requested: 0b1,
      scope_key_match: true,
      ttl_respected: false,
    });
    expect(r.score).toBe(60);
    expect(r.outcome).toBe('WARN');
  });

  // Axis 4: proportional_force
  it('HM-023: proportional_force — mode 1 → 100 PASS', () => {
    const r = scoreAxis({ axis: 'proportional_force', response_mode: 1 });
    expect(r.score).toBe(100);
  });

  it('HM-024: proportional_force — mode 2 WITH standing order → 100 PASS', () => {
    const r = scoreAxis({ axis: 'proportional_force', response_mode: 2, standing_order_exists: true });
    expect(r.score).toBe(100);
  });

  it('HM-025: proportional_force — mode 2 WITHOUT standing order → 0 FAIL', () => {
    const r = scoreAxis({ axis: 'proportional_force', response_mode: 2, standing_order_exists: false });
    expect(r.score).toBe(0);
    expect(r.outcome).toBe('FAIL');
  });

  it('HM-026: proportional_force — mode 3 always permitted', () => {
    const r = scoreAxis({ axis: 'proportional_force', response_mode: 3 });
    expect(r.score).toBe(100);
    expect(r.notes[0]).toContain('mode-3 existential action');
  });

  // Axis 5: return_with_proof
  it('HM-027: return_with_proof — all good → 100 PASS', () => {
    const r = scoreAxis({
      axis: 'return_with_proof',
      receipt_filed: true,
      receipt_signed: true,
      actions_listed: true,
      deviations_reported: true,
    });
    expect(r.score).toBe(100);
  });

  it('HM-028: return_with_proof — no receipt filed → 0 FAIL', () => {
    const r = scoreAxis({ axis: 'return_with_proof', receipt_filed: false });
    expect(r.score).toBe(0);
    expect(r.outcome).toBe('FAIL');
  });

  // Axis 6: no_overreach
  it('HM-029: no_overreach — used ⊆ granted, low utilisation → 100 PASS', () => {
    const r = scoreAxis({
      axis: 'no_overreach',
      trust_mask_granted: 0b11111,
      trust_mask_used: 0b00111,  // 3 of 5 bits = 60%
    });
    expect(r.score).toBe(100);
  });

  it('HM-030: no_overreach — used has bits NOT granted → 0 FAIL', () => {
    const r = scoreAxis({
      axis: 'no_overreach',
      trust_mask_granted: 0b00001,
      trust_mask_used: 0b00011,  // bit 1 used but not granted
    });
    expect(r.score).toBe(0);
    expect(r.outcome).toBe('FAIL');
    expect(r.notes[0]).toContain('overreach');
  });

  it('HM-031: no_overreach — high utilisation (>80%) → 80 PASS with warning note', () => {
    const r = scoreAxis({
      axis: 'no_overreach',
      trust_mask_granted: 0b11111,
      trust_mask_used: 0b11111,  // 100% utilisation
    });
    expect(r.score).toBe(80);
    expect(r.notes[0]).toContain('high utilisation');
  });

  // Axis 7: truthful_report
  it('HM-032: truthful_report — all good → 100 PASS', () => {
    const r = scoreAxis({
      axis: 'truthful_report',
      before_state_present: true,
      after_state_present: true,
      errors_reported: true,
      human_modified_flagged: true,
    });
    expect(r.score).toBe(100);
  });

  it('HM-033: truthful_report — missing before+after → 40 FAIL', () => {
    const r = scoreAxis({
      axis: 'truthful_report',
      before_state_present: false,
      after_state_present: false,
      errors_reported: true,
      human_modified_flagged: true,
    });
    expect(r.score).toBe(40);
    expect(r.outcome).toBe('FAIL');
  });
});

// ─── §3 computePostureScore (HNG-YK-001 worst-axis floor) ─────────────────────

describe('§3 computePostureScore', () => {
  beforeEach(() => setEventBus(null));

  function allPassingAxes(): AxisScore[] {
    return [
      scoreAxis({ axis: 'mudrika_integrity', mudrika_verified: true, mudrika_ttl_remaining_s: 600, pramana_chain_depth: 2 }),
      scoreAxis({ axis: 'identity_broadcast', self_declared: true, declared_fields: ['agentId', 'agentType', 'officerRole', 'scopeKey', 'taskId', 'delegatedBy'] }),
      scoreAxis({ axis: 'mandate_bounds', trust_mask_granted: 0b11111, trust_mask_requested: 0b01111, scope_key_match: true, ttl_respected: true }),
      scoreAxis({ axis: 'proportional_force', response_mode: 1 }),
      scoreAxis({ axis: 'return_with_proof', receipt_filed: true, receipt_signed: true, actions_listed: true, deviations_reported: true }),
      scoreAxis({ axis: 'no_overreach', trust_mask_granted: 0b11111, trust_mask_used: 0b00111 }),
      scoreAxis({ axis: 'truthful_report', before_state_present: true, after_state_present: true, errors_reported: true, human_modified_flagged: true }),
    ];
  }

  it('HM-034: all 7 axes PASS → grade A, score 100', () => {
    const posture = computePostureScore(allPassingAxes());
    expect(posture.overall_grade).toBe('A');
    expect(posture.overall_score).toBe(100);
    expect(posture.violation_count).toBe(0);
    expect(posture.warn_count).toBe(0);
  });

  it('HM-035: HNG-YK-001 worst-axis floor — single FAIL caps grade at D regardless of average', () => {
    const axes = allPassingAxes();
    // Override one axis to FAIL
    axes[0] = scoreAxis({ axis: 'mudrika_integrity', mudrika_verified: false });
    const posture = computePostureScore(axes);
    expect(posture.violation_count).toBe(1);
    expect(posture.overall_grade).toBe('D');  // floor enforced — not C/B/A despite avg ~86
    // Average is (0+100+100+100+100+100+100)/7 ≈ 86 — that would normally be B,
    // but the floor caps it at D because there's a violation.
    expect(posture.overall_score).toBeGreaterThanOrEqual(85);
  });

  it('HM-036: 3+ violations → grade F', () => {
    const axes = allPassingAxes();
    axes[0] = scoreAxis({ axis: 'mudrika_integrity', mudrika_verified: false });
    axes[1] = scoreAxis({ axis: 'identity_broadcast', self_declared: false });
    axes[2] = scoreAxis({ axis: 'mandate_bounds', trust_mask_granted: 0, trust_mask_requested: 0xff, scope_key_match: true, ttl_respected: true });
    const posture = computePostureScore(axes);
    expect(posture.violation_count).toBeGreaterThanOrEqual(3);
    expect(posture.overall_grade).toBe('F');
  });

  it('HM-037: clean A-grade with WARN axis → grade reflects average', () => {
    const axes = allPassingAxes();
    // Replace one axis with a WARN (score 70)
    axes[1] = scoreAxis({ axis: 'identity_broadcast', self_declared: true, declared_fields: ['agentId', 'agentType', 'officerRole'] });
    const posture = computePostureScore(axes);
    expect(posture.warn_count).toBe(1);
    expect(posture.violation_count).toBe(0);
    // avg = (100*6 + 70)/7 ≈ 96 → grade A
    expect(posture.overall_grade).toBe('A');
  });

  it('HM-038: empty axis list → score 0 grade D, no crash', () => {
    const posture = computePostureScore([]);
    expect(posture.overall_score).toBe(0);
    expect(posture.overall_grade).toBe('D');
  });

  it('HM-039: axes object keyed by axis name', () => {
    const posture = computePostureScore(allPassingAxes());
    expect(posture.axes.mudrika_integrity).toBeDefined();
    expect(posture.axes.truthful_report).toBeDefined();
    expect(posture.axes.mudrika_integrity.outcome).toBe('PASS');
  });
});

// ─── §4 ACC bus emission (ACC-003, ACC-YK-003, INF-ACC-005) ───────────────────

describe('§4 ACC bus emission', () => {
  beforeEach(() => setEventBus(null));

  it('HM-040: isBusWired false by default; setEventBus toggles', () => {
    expect(isBusWired()).toBe(false);
    setEventBus({ emit: () => {} });
    expect(isBusWired()).toBe(true);
    setEventBus(null);
    expect(isBusWired()).toBe(false);
  });

  it('HM-041: verifyMudrika PASS emits primitive=hanumang-mandate + event_type=mudrika.verified', () => {
    const received: AccReceipt[] = [];
    setEventBus({ emit: (r) => received.push(r) });
    const m = validMudrika();
    verifyMudrika(m, m.agent_id);
    expect(received.length).toBe(1);
    expect(received[0].primitive).toBe('hanumang-mandate');
    expect(received[0].event_type).toBe('mudrika.verified');
    expect(received[0].verdict).toBe('PASS');
    expect(received[0].agent_id).toBe(m.agent_id);
    expect(received[0].rules_fired).toContain('HNG-S-008');
  });

  it('HM-042: verifyMudrika FAIL emits mudrika.rejected with verdict=FAIL', () => {
    const received: AccReceipt[] = [];
    setEventBus({ emit: (r) => received.push(r) });
    verifyMudrika({ mudrika_id: 'incomplete' });
    expect(received.length).toBe(1);
    expect(received[0].event_type).toBe('mudrika.rejected');
    expect(received[0].verdict).toBe('FAIL');
  });

  it('HM-043: verifyMudrika EXPIRED emits with verdict=EXPIRED', () => {
    const received: AccReceipt[] = [];
    setEventBus({ emit: (r) => received.push(r) });
    const m = validMudrika({
      issued_at: new Date(Date.now() - 7200_000).toISOString(),
      ttl_seconds: 3600,
    });
    verifyMudrika(m, m.agent_id);
    expect(received[0].event_type).toBe('mudrika.rejected');
    expect(received[0].verdict).toBe('EXPIRED');
    expect(received[0].rules_fired).toContain('HNG-S-009');
  });

  it('HM-044: scoreAxis emits posture.axis_scored per call', () => {
    const received: AccReceipt[] = [];
    setEventBus({ emit: (r) => received.push(r) });
    scoreAxis({ axis: 'mudrika_integrity', mudrika_verified: true, mudrika_ttl_remaining_s: 600 });
    expect(received.length).toBe(1);
    expect(received[0].event_type).toBe('posture.axis_scored');
    expect(received[0].verdict).toBe('PASS');
  });

  it('HM-045: computePostureScore emits posture.scored aggregate with grade-verdict format', () => {
    const received: AccReceipt[] = [];
    const axes = [
      scoreAxis({ axis: 'mudrika_integrity', mudrika_verified: true, mudrika_ttl_remaining_s: 600, pramana_chain_depth: 2 }),
      scoreAxis({ axis: 'identity_broadcast', self_declared: true, declared_fields: ['agentId', 'agentType', 'officerRole', 'scopeKey', 'taskId', 'delegatedBy'] }),
    ];
    // Wire bus AFTER scoring axes so we only catch posture.scored
    setEventBus({ emit: (r) => received.push(r) });
    computePostureScore(axes);
    expect(received.length).toBe(1);
    expect(received[0].event_type).toBe('posture.scored');
    expect(received[0].verdict).toMatch(/^[ABCDF]-(PASS|WARN|FAIL)$/);
  });

  it('HM-046: emit failure swallowed — caller unaffected (INF-ACC-005)', () => {
    setEventBus({ emit: () => { throw new Error('bus exploded'); } });
    expect(() => {
      verifyMudrika(validMudrika());
    }).not.toThrow();
    expect(() => {
      scoreAxis({ axis: 'mudrika_integrity', mudrika_verified: true });
    }).not.toThrow();
  });
});
