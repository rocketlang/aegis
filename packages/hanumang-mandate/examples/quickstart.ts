#!/usr/bin/env bun
// @xshieldai/hanumang-mandate — runnable quickstart
//
// What you'll see: 3 mudrika verifications (PASS / EXPIRED / FAIL) +
// 7-axis posture scored two ways (clean A-grade vs. worst-axis-floor D-grade).
// Run: bun run packages/hanumang-mandate/examples/quickstart.ts

import {
  setEventBus,
  verifyMudrika,
  scoreAxis,
  computePostureScore,
  type AccReceipt,
  type MudrikaPayload,
} from '../src/index.js';

setEventBus({
  emit: (r: AccReceipt) =>
    console.log(`📜 ${r.event_type.padEnd(22)} verdict=${(r.verdict ?? '').padEnd(10)} ${r.summary ?? ''}`),
});

function makeMudrika(over: Partial<MudrikaPayload> = {}): MudrikaPayload {
  return {
    mudrika_version: 'v1',
    mudrika_id: `mdr-demo-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
    principal_id: 'user:capt-anil',
    agent_id: 'agent:codex-001',
    task_id: 'task:refactor-routes',
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

console.log('\n=== Mudrika verification — 3 cases ===\n');

console.log('▶ Case 1: valid mudrika');
const r1 = verifyMudrika(makeMudrika(), 'agent:codex-001');
console.log(`  outcome=${r1.outcome} trust_mask=0b${r1.trust_mask.toString(2)} expires_at=${r1.expires_at}\n`);

console.log('▶ Case 2: expired mudrika (issued 2h ago, TTL 1h)');
const r2 = verifyMudrika(makeMudrika({
  issued_at: new Date(Date.now() - 7200_000).toISOString(),
  ttl_seconds: 3600,
}), 'agent:codex-001');
console.log(`  outcome=${r2.outcome} failure_reason=${r2.failure_reason}\n`);

console.log('▶ Case 3: agent_id mismatch');
const r3 = verifyMudrika(makeMudrika({ agent_id: 'agent:wrong' }), 'agent:expected');
console.log(`  outcome=${r3.outcome} failure_reason=${r3.failure_reason}\n`);

console.log('=== 7-axis posture — clean run (all axes PASS) ===\n');
const axesGood = [
  scoreAxis({ axis: 'mudrika_integrity', mudrika_verified: true, mudrika_ttl_remaining_s: 600, pramana_chain_depth: 2, task_id: 'demo-1' }),
  scoreAxis({ axis: 'identity_broadcast', self_declared: true, declared_fields: ['agentId', 'agentType', 'officerRole', 'scopeKey', 'taskId', 'delegatedBy'], task_id: 'demo-1' }),
  scoreAxis({ axis: 'mandate_bounds', trust_mask_granted: 0b11111, trust_mask_requested: 0b01111, scope_key_match: true, ttl_respected: true, task_id: 'demo-1' }),
  scoreAxis({ axis: 'proportional_force', response_mode: 1, task_id: 'demo-1' }),
  scoreAxis({ axis: 'return_with_proof', receipt_filed: true, receipt_signed: true, actions_listed: true, deviations_reported: true, task_id: 'demo-1' }),
  scoreAxis({ axis: 'no_overreach', trust_mask_granted: 0b11111, trust_mask_used: 0b00111, task_id: 'demo-1' }),
  scoreAxis({ axis: 'truthful_report', before_state_present: true, after_state_present: true, errors_reported: true, human_modified_flagged: true, task_id: 'demo-1' }),
];
const postureGood = computePostureScore(axesGood);
console.log(`\n  → overall_grade=${postureGood.overall_grade} score=${postureGood.overall_score}/100 violations=${postureGood.violation_count}\n`);

console.log('=== 7-axis posture — HNG-YK-001 worst-axis floor demo (one FAIL caps at D) ===\n');
const axesBad = [...axesGood];
// Replace one axis with a FAIL — average stays high but grade falls to D
axesBad[0] = scoreAxis({ axis: 'mudrika_integrity', mudrika_verified: false, task_id: 'demo-2' });
const postureBad = computePostureScore(axesBad);
console.log(`\n  → overall_grade=${postureBad.overall_grade} score=${postureBad.overall_score}/100 violations=${postureBad.violation_count}`);
console.log(`  (HNG-YK-001 invariant: even with avg ~${postureBad.overall_score}, single FAIL caps grade at D)`);

console.log('\n✅ hanumang-mandate quickstart complete — mudrika + 7-axis + worst-axis-floor demonstrated.');
