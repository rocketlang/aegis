// SPDX-License-Identifier: AGPL-3.0-only
// The reference gate's verifier tests (gtp-gate test/verify.test.mjs), carried unchanged in substance.
// Run: bun test
import { test } from 'bun:test';
import assert from 'node:assert/strict';
import { verifyTurn, refusalBody } from '../src/index';

// ── fixtures ──────────────────────────────────────────────────────────────
const M = (...bits) => bits.reduce((m, b) => m | (1 << b), 0);
const OPERATOR = M(8, 9, 12, 19);   // read + bid + backhaul + ebl.transfer (money)
const VIEWER = M(12);               // read only

const catalog = {
  'loadboard.read': { bit: 12, verb: 'can_read', reversibility: 'reversible' },
  'bid.place':      { bit: 8,  verb: 'can_act',  reversibility: 'reversible' },
  'backhaul.offer': { bit: 9,  verb: 'can_act',  reversibility: 'compensable' },
  'ebl.transfer':   { bit: 19, verb: 'can_act',  reversibility: 'irreversible' }, // the money turn
};
const ctx = (over = {}) => ({ sessionMask: OPERATOR, driverTrustMask: OPERATOR, catalog, sealedBudgetLeft: 100, level: 'L4', ...over });
const agent = (slug, verb, bit, over = {}) => ({ driver: { type: 'agent', id: 'a1' }, capability: { service: 'fr8x', slug, verb, bit }, ...over });

// ── happy paths ─────────────────────────────────────────────────────────────
test('agent read with bit in masks → PASS', () => {
  const v = verifyTurn(agent('loadboard.read', 'can_read', 12), ctx());
  assert.equal(v.status, 'PASS');
  assert.equal(v.httpCode, 200);
});

test('agent reversible write, intent present, auto-commit → PASS', () => {
  const v = verifyTurn(agent('bid.place', 'can_act', 8, { commit: 'auto', intent: { present: true } }), ctx());
  assert.equal(v.status, 'PASS');
  assert.equal(v.reversibility, 'reversible');
});

// ── gated pause ───────────────────────────────────────────────────────────
test('irreversible write with auto-commit is FORCED to pause → 423 (GTP-009)', () => {
  const v = verifyTurn(agent('ebl.transfer', 'can_act', 19, { commit: 'auto', intent: { present: true } }), ctx());
  assert.equal(v.status, 'PAUSED');
  assert.equal(v.httpCode, 423);
  assert.equal(v.rule, 'GTP-007');
  assert.equal(v.approvalRequired, true);
});

test('explicit pause-commit write → 423', () => {
  const v = verifyTurn(agent('bid.place', 'can_act', 8, { commit: 'pause', intent: { present: true } }), ctx());
  assert.equal(v.status, 'PAUSED');
});

// ── the fr8x S5 regression: structural self-approval impossibility ──────────
test('S5: agent lacking the money bit is REFUSED (GTP-INV-6) — bounded driver', () => {
  // agent's trust_mask does NOT include bit 19 (ebl.transfer / money)
  const v = verifyTurn(agent('ebl.transfer', 'can_act', 19, { commit: 'pause', intent: { present: true } }),
    ctx({ driverTrustMask: VIEWER }));
  assert.equal(v.status, 'REFUSED');
  assert.equal(v.httpCode, 403);
  assert.equal(v.rule, 'GTP-INV-6');
});

test('S5: a self-asserted "approved" flag CANNOT flip the refusal — there is no approval input', () => {
  // mirrors the original fr8x hole: caller tries to self-approve. The verifier has
  // no `approved` parameter, so the extra field is inert — still REFUSED.
  const env = agent('ebl.transfer', 'can_act', 19, { commit: 'pause', intent: { present: true }, approved: true, xFr8xApproved: 'true' });
  const v = verifyTurn(env, ctx({ driverTrustMask: VIEWER }));
  assert.equal(v.status, 'REFUSED');
  assert.equal(v.rule, 'GTP-INV-6');
});

test('a HUMAN holding the money bit IS authorized for the same turn (human disposes)', () => {
  const human = { driver: { type: 'human', id: 'desk@fr8x' }, capability: { service: 'fr8x', slug: 'ebl.transfer', verb: 'can_act', bit: 19 }, commit: 'pause', intent: { present: true } };
  const v = verifyTurn(human, ctx({ driverTrustMask: OPERATOR }));
  assert.equal(v.status, 'PAUSED');      // authorized → held for commit (not refused)
  assert.equal(v.approvalRequired, true);
});

// ── capability refusals ─────────────────────────────────────────────────────
test('unknown slug → 403 GTP-006', () => {
  const v = verifyTurn(agent('ghost.capability', 'can_read', 12), ctx());
  assert.equal(v.httpCode, 403);
  assert.equal(v.code, 'GTP_CAPABILITY_DENIED');
});

test('claimed bit ≠ catalog bit → 403 (lying about the bit)', () => {
  const v = verifyTurn(agent('loadboard.read', 'can_read', 7), ctx());
  assert.equal(v.status, 'REFUSED');
  assert.match(v.detail, /catalog bit 12/);
});

test('verb mismatch → 403', () => {
  const v = verifyTurn(agent('loadboard.read', 'can_act', 12, { intent: { present: true } }), ctx());
  assert.equal(v.status, 'REFUSED');
});

test('session_mask lacks bit (even if trust_mask has it) → 403', () => {
  const v = verifyTurn(agent('bid.place', 'can_act', 8, { intent: { present: true } }), ctx({ sessionMask: VIEWER }));
  assert.equal(v.status, 'REFUSED');
  assert.equal(v.rule, 'GTP-006');
});

// ── intent ──────────────────────────────────────────────────────────────────
test('can_act without intent → 403 GTP_INTENT_MISSING', () => {
  const v = verifyTurn(agent('bid.place', 'can_act', 8, { commit: 'auto' }), ctx());
  assert.equal(v.code, 'GTP_INTENT_MISSING');
});

test('ChittaGuard intent fail → 403 GTP_INTENT_REFUSED', () => {
  const v = verifyTurn(agent('bid.place', 'can_act', 8, { intent: { present: true } }), ctx({ intentVerdict: 'fail' }));
  assert.equal(v.code, 'GTP_INTENT_REFUSED');
});

// ── reversibility ─────────────────────────────────────────────────────────
test('self-softened reversibility claim → 403 GTP_REVERSIBILITY_MISMATCH', () => {
  const v = verifyTurn(agent('ebl.transfer', 'can_act', 19, { commit: 'pause', intent: { present: true }, reversibilityClaim: 'reversible' }), ctx());
  assert.equal(v.code, 'GTP_REVERSIBILITY_MISMATCH');
});

// ── authority / budget / attenuation ────────────────────────────────────────
test('budget exhausted → 402', () => {
  const v = verifyTurn(agent('loadboard.read', 'can_read', 12), ctx({ sealedBudgetLeft: 0 }));
  assert.equal(v.httpCode, 402);
  assert.equal(v.code, 'GTP_BUDGET_EXHAUSTED');
});

test('declared budget above sealed → 403 GTP_AUTHORITY_LIE', () => {
  const v = verifyTurn(agent('loadboard.read', 'can_read', 12, { authority: { declaredBudgetLeft: 999 } }), ctx({ sealedBudgetLeft: 10 }));
  assert.equal(v.code, 'GTP_AUTHORITY_LIE');
});

test('spawn-invariant: driver mask exceeds parent → 403 GTP-INV-2', () => {
  const v = verifyTurn(agent('loadboard.read', 'can_read', 12), ctx({ parentMask: VIEWER, driverTrustMask: OPERATOR }));
  // OPERATOR has bits parent lacks → attenuation violated
  assert.equal(v.rule, 'GTP-INV-2');
});

// ── malformed ───────────────────────────────────────────────────────────────
test('missing capability → 400', () => {
  const v = verifyTurn({ driver: { type: 'agent', id: 'a1' } }, ctx());
  assert.equal(v.httpCode, 400);
});

// ── determinism & purity (tokenless: no I/O, no model) ──────────────────────
test('determinism: identical inputs → identical verdict', () => {
  const env = agent('ebl.transfer', 'can_act', 19, { commit: 'auto', intent: { present: true } });
  const a = verifyTurn(env, ctx());
  const b = verifyTurn(env, ctx());
  assert.deepEqual(a, b);
});

// ── refusal body shaping ────────────────────────────────────────────────────
test('refusalBody names rule + is recoverable for a 403', () => {
  const v = verifyTurn(agent('ebl.transfer', 'can_act', 19, { commit: 'pause', intent: { present: true } }), ctx({ driverTrustMask: VIEWER }));
  const body = refusalBody('t_test', v);
  assert.equal(body.rule, 'GTP-INV-6');
  assert.equal(body.recoverable, true);
  assert.match(body.recovery, /Nallasetu|escalated/);
});
