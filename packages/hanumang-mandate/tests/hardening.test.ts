// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.

// @xshieldai/hanumang-mandate — malformed input and missing evidence (v0.3.0)
//
// Two questions, asked together because either one alone can be answered by a broken
// verifier: is malformed or missing evidence refused (HNG-S-012, HNG-S-013), and is a
// genuine caller still accepted?

import { describe, it, expect, beforeEach } from 'bun:test';
import { verifyMudrika, scoreAxis, computePostureScore, setEventBus, MAX_TTL_SECONDS } from '../src/index.js';

const good = () => ({
  mudrika_version: 'v1',
  mudrika_id: 'mud-h',
  principal_id: 'principal-1',
  agent_id: 'agent-1',
  task_id: 'task-1',
  trust_mask: 0b1011,
  scope_key: 'invoices:read',
  issued_at: new Date(Date.now() - 60_000).toISOString(),
  ttl_seconds: 3600,
  required_return_proof: 'receipt',
  revocation_url: 'https://example.invalid/revoke',
  pramana_chain: ['root'],
  signature: 'sig',
});
const seven = () =>
  [
    scoreAxis({ axis: 'mudrika_integrity', mudrika_verified: true, mudrika_ttl_remaining_s: 600, pramana_chain_depth: 1 }),
    scoreAxis({ axis: 'identity_broadcast', self_declared: true, declared_fields: ['agentId', 'agentType', 'officerRole', 'scopeKey', 'taskId', 'delegatedBy'] }),
    scoreAxis({ axis: 'mandate_bounds', trust_mask_requested: 0b0011, trust_mask_granted: 0b1011, scope_key_match: true, ttl_respected: true }),
    scoreAxis({ axis: 'proportional_force', response_mode: 1 }),
    scoreAxis({ axis: 'return_with_proof', receipt_filed: true, receipt_signed: true, actions_listed: true, deviations_reported: true }),
    scoreAxis({ axis: 'no_overreach', trust_mask_granted: 0b11111111, trust_mask_used: 0b0011 }),
    scoreAxis({ axis: 'truthful_report', before_state_present: true, after_state_present: true, errors_reported: true, human_modified_flagged: true }),
  ] as any[];

describe('§5 verifyMudrika refuses malformed credentials (HNG-S-012)', () => {
  beforeEach(() => setEventBus(null));

  const refused: [string, () => unknown, string][] = [
    ['HD-001 issued in the year 2099', () => ({ ...good(), issued_at: '2099-01-01T00:00:00Z' }), 'issued_in_future'],
    ['HD-002 ttl_seconds of 1e18', () => ({ ...good(), ttl_seconds: 1e18 }), 'invalid_ttl_seconds'],
    ['HD-003 ttl_seconds is Infinity', () => ({ ...good(), ttl_seconds: Infinity }), 'invalid_ttl_seconds'],
    ['HD-004 ttl_seconds is text', () => ({ ...good(), ttl_seconds: 'forever' }), 'invalid_ttl_seconds'],
    ['HD-005 ttl_seconds negative', () => ({ ...good(), ttl_seconds: -5 }), 'invalid_ttl_seconds'],
    ['HD-006 ttl_seconds beyond one year', () => ({ ...good(), ttl_seconds: MAX_TTL_SECONDS + 1 }), 'invalid_ttl_seconds'],
    ['HD-007 trust_mask is NaN', () => ({ ...good(), trust_mask: NaN }), 'invalid_trust_mask'],
    ['HD-008 trust_mask is text', () => ({ ...good(), trust_mask: 'admin' }), 'invalid_trust_mask'],
    ['HD-009 trust_mask is 1.5', () => ({ ...good(), trust_mask: 1.5 }), 'invalid_trust_mask'],
    ['HD-010 pramana_chain is text', () => ({ ...good(), pramana_chain: 'root' }), 'invalid_pramana_chain'],
    ['HD-011 scope_key is an object', () => ({ ...good(), scope_key: {} }), 'invalid_field_type: scope_key'],
    ['HD-012 agent_id is a list holding the right id', () => ({ ...good(), agent_id: ['agent-1'] }), 'invalid_field_type: agent_id'],
    ['HD-013 an unknown version', () => ({ ...good(), mudrika_version: 'v2' }), 'unsupported_mudrika_version'],
    ['HD-014 the credential is a list', () => [good()], 'mudrika_missing'],
    ['HD-015 fields supplied only through the prototype', () => Object.create(good()), 'missing_required_fields'],
  ];
  for (const [name, make, reason] of refused) {
    it(`${name} → FAIL (${reason})`, () => {
      const r = verifyMudrika(make(), 'agent-1');
      expect(r.outcome).toBe('FAIL');
      expect(r.failure_reason).toBe(reason);
    });
  }

  it('HD-016 an empty expected agent id is refused, not skipped', () => {
    expect(verifyMudrika(good(), '').failure_reason).toBe('invalid_expected_agent_id');
    expect(verifyMudrika(good(), null as any).failure_reason).toBe('invalid_expected_agent_id');
  });

  it('HD-017 none of the malformed inputs makes the function throw', () => {
    for (const [, make] of refused) expect(() => verifyMudrika(make(), 'agent-1')).not.toThrow();
  });

  it('HD-018 every result says the signature was not verified', () => {
    expect(verifyMudrika(good(), 'agent-1').signature_verified).toBe(false);
    expect(verifyMudrika({}, 'agent-1').signature_verified).toBe(false);
  });
});

describe('§6 verifyMudrika still accepts genuine credentials', () => {
  beforeEach(() => setEventBus(null));

  const accepted: [string, () => [unknown, string?]][] = [
    ['HD-020 no expected agent id given', () => [good()]],
    ['HD-021 no version field', () => { const m: any = good(); delete m.mudrika_version; return [m, 'agent-1']; }],
    ['HD-022 version "1.2"', () => [{ ...good(), mudrika_version: '1.2' }, 'agent-1']],
    ['HD-023 no trust_mask field', () => { const m: any = good(); delete m.trust_mask; return [m, 'agent-1']; }],
    ['HD-024 all 32 mask bits', () => [{ ...good(), trust_mask: 0xffffffff }, 'agent-1']],
    ['HD-025 issued two minutes ahead of this clock', () => [{ ...good(), issued_at: new Date(Date.now() + 120_000).toISOString() }, 'agent-1']],
    ['HD-026 a thirty-day ttl', () => [{ ...good(), ttl_seconds: 30 * 86400 }, 'agent-1']],
    ['HD-027 parsed from JSON text', () => [JSON.parse(JSON.stringify(good())), 'agent-1']],
  ];
  for (const [name, make] of accepted) {
    it(`${name} → PASS`, () => {
      const [m, expected] = make();
      expect(verifyMudrika(m, expected).outcome).toBe('PASS');
    });
  }
});

describe('§7 scoreAxis: missing or malformed evidence is a FAIL (HNG-S-013)', () => {
  beforeEach(() => setEventBus(null));

  const failing: [string, any][] = [
    ['HD-030 mandate_bounds with no masks', { axis: 'mandate_bounds' }],
    ['HD-031 mandate_bounds: bit 32 requested, not granted', { axis: 'mandate_bounds', trust_mask_requested: 2 ** 32, trust_mask_granted: 1, scope_key_match: true }],
    ['HD-032 mandate_bounds: a NaN mask', { axis: 'mandate_bounds', trust_mask_requested: NaN, trust_mask_granted: 1, scope_key_match: true }],
    ['HD-033 no_overreach with no masks', { axis: 'no_overreach' }],
    ['HD-034 no_overreach: nothing granted, bits used', { axis: 'no_overreach', trust_mask_granted: 0, trust_mask_used: 255 }],
    ['HD-035 no_overreach: bit 32 used, not granted', { axis: 'no_overreach', trust_mask_granted: 1, trust_mask_used: 2 ** 32 + 1 }],
    ['HD-036 proportional_force: no mode declared', { axis: 'proportional_force' }],
    ['HD-037 proportional_force: mode given as text', { axis: 'proportional_force', response_mode: '2' }],
    ['HD-038 proportional_force: a mode that does not exist', { axis: 'proportional_force', response_mode: 7 }],
    ['HD-039 mudrika_integrity: verified given as the text "false"', { axis: 'mudrika_integrity', mudrika_verified: 'false' }],
    ['HD-040 identity_broadcast: fields given as one long text', { axis: 'identity_broadcast', self_declared: true, declared_fields: 'agentId agentType officerRole scopeKey taskId delegatedBy' }],
    ['HD-041 an axis that does not exist', { axis: 'made_up_axis' }],
    ['HD-042 no input at all', null],
  ];
  for (const [name, input] of failing) {
    it(`${name} → FAIL`, () => {
      expect(scoreAxis(input).outcome).toBe('FAIL');
    });
  }

  it('HD-043 mandate_bounds without scope evidence is a WARN, not a pass', () => {
    const r = scoreAxis({ axis: 'mandate_bounds', trust_mask_requested: 1, trust_mask_granted: 1 });
    expect(r.outcome).toBe('WARN');
  });

  it('HD-044 masks above bit 31 are compared whole', () => {
    expect(scoreAxis({ axis: 'no_overreach', trust_mask_granted: 2 ** 40 + 0b1111111, trust_mask_used: 2 ** 40 }).outcome).toBe('PASS');
    expect(scoreAxis({ axis: 'mandate_bounds', trust_mask_requested: 2 ** 40, trust_mask_granted: 0b1111, scope_key_match: true }).outcome).toBe('FAIL');
  });

  it('HD-045 nothing granted and nothing used is a pass', () => {
    expect(scoreAxis({ axis: 'no_overreach', trust_mask_granted: 0, trust_mask_used: 0 }).outcome).toBe('PASS');
  });
});

describe('§8 computePostureScore grades all seven axes, each once (HNG-S-013)', () => {
  beforeEach(() => setEventBus(null));

  it('HD-050 one axis supplied, six absent → not A or B', () => {
    const p = computePostureScore([seven()[0]]);
    expect(['A', 'B']).not.toContain(p.overall_grade);
    expect(p.axes_missing.length).toBe(6);
  });
  it('HD-051 the same axis seven times → not A or B', () => {
    const p = computePostureScore(Array.from({ length: 7 }, () => seven()[0]));
    expect(['A', 'B']).not.toContain(p.overall_grade);
    expect(p.axes_invalid.some((x) => x.startsWith('duplicate axis'))).toBe(true);
  });
  it('HD-052 a score outside 0–100 is a violation', () => {
    const p = computePostureScore(seven().map((a) => ({ ...a, score: 1000 })));
    expect(p.overall_grade).toBe('F');
    expect(p.overall_score).toBe(0);
  });
  it('HD-053 an outcome that disagrees with its score is recomputed', () => {
    const a = seven();
    a[3] = { ...a[3], score: 0, outcome: 'PASS' };
    const p = computePostureScore(a);
    expect(p.axes.proportional_force.outcome).toBe('FAIL');
    expect(p.overall_grade).toBe('D');
  });
  it('HD-054 an extra axis with a made-up name is a violation', () => {
    const p = computePostureScore([...seven(), { axis: 'bonus', score: 100, outcome: 'PASS', rule_id: 'x', notes: [] } as any]);
    expect(['A', 'B']).not.toContain(p.overall_grade);
  });
  it('HD-055 a null in the list, or no list at all, does not throw', () => {
    const a = seven();
    a[4] = null;
    expect(() => computePostureScore(a)).not.toThrow();
    expect(() => computePostureScore({ length: 7 } as any)).not.toThrow();
    expect(computePostureScore({ length: 7 } as any).overall_grade).toBe('F');
  });
  it('HD-056 seven genuine axes in any order, or after a JSON round trip, still grade A', () => {
    expect(computePostureScore(seven().reverse()).overall_grade).toBe('A');
    expect(computePostureScore(JSON.parse(JSON.stringify(seven()))).overall_grade).toBe('A');
  });
});

describe('§9 stated limits — these are accepted, and the README says so', () => {
  beforeEach(() => setEventBus(null));
  // If one of these starts being refused, the README's limits section is out of date.
  it('LIM-001 a made-up signature is accepted (signature_verified stays false)', () => {
    const r = verifyMudrika({ ...good(), signature: 'completely-fake' }, 'agent-1');
    expect(r.outcome).toBe('PASS');
    expect(r.signature_verified).toBe(false);
  });
  it('LIM-002 seven hand-written axis objects with plausible scores are graded', () => {
    const names = ['mudrika_integrity', 'identity_broadcast', 'mandate_bounds', 'proportional_force', 'return_with_proof', 'no_overreach', 'truthful_report'] as const;
    const p = computePostureScore(names.map((axis) => ({ axis, score: 100, outcome: 'PASS', rule_id: 'x', notes: [] }) as any));
    expect(p.overall_grade).toBe('A');
  });
  it('LIM-003 mode 3 needs no standing order', () => {
    expect(scoreAxis({ axis: 'proportional_force', response_mode: 3 }).outcome).toBe('PASS');
  });
});
