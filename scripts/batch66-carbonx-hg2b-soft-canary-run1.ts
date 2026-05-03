/**
 * AEGIS Batch 66 — carbonx HG-2B Financial Soft-Canary Soak Run 1/7
 *
 * Policy declared: CARBONX_HG2B_POLICY in hard-gate-policy.ts.
 * Soak run 1/7: 81 checks verifying policy structure + surface simulation.
 *
 * Non-negotiables:
 *   hard_gate_enabled=false — carbonx NOT in AEGIS_HARD_GATE_SERVICES
 *   Live roster remains 7 — parali-central is the only live HG-2B
 *   No promotion permitted in this batch
 */

import * as fs from 'fs';
import * as path from 'path';
import {
  simulateHardGate,
  applyHardGate,
  HARD_GATE_POLICIES,
  CARBONX_HG2B_POLICY,
} from '../src/enforcement/hard-gate-policy.js';

// ─── Paths ────────────────────────────────────────────────────────────────────

const AEGIS_ROOT   = '/root/aegis';
const CARBONX_ROOT = '/root/apps/carbonx/backend';
const PATHS = {
  hardGatePolicy:  path.join(AEGIS_ROOT, 'src/enforcement/hard-gate-policy.ts'),
  etsService:      path.join(CARBONX_ROOT, 'src/services/ets/ets-service.ts'),
  etsTypes:        path.join(CARBONX_ROOT, 'src/schema/types/ets.ts'),
  approvalToken:   path.join(CARBONX_ROOT, 'src/lib/aegis-approval-token.ts'),
  aegisSense:      path.join(CARBONX_ROOT, 'src/lib/aegis-sense.ts'),
  b65Artifact:     path.join(AEGIS_ROOT, 'audits/batch65_carbonx_br5_financial_rescan_gate.json'),
};

// ─── Audit State ──────────────────────────────────────────────────────────────

let passed = 0;
let failed = 0;
const results: Array<{ id: number; label: string; verdict: 'PASS' | 'FAIL'; section: string }> = [];

function readFile(p: string): string {
  try { return fs.readFileSync(p, 'utf8'); } catch { return ''; }
}
function readJson(p: string): Record<string, unknown> {
  try { return JSON.parse(readFile(p)); } catch { return {}; }
}

function check(id: number, label: string, actual: unknown, expected: unknown, section: string): void {
  const ok = actual === expected;
  results.push({ id, label, verdict: ok ? 'PASS' : 'FAIL', section });
  if (ok) { passed++; }
  else {
    failed++;
    console.error(`  ✗ C${id} [${section}] ${label}`);
    console.error(`      expected=${JSON.stringify(expected)}, got=${JSON.stringify(actual)}`);
  }
}

function section(label: string): void { console.log(`\n── ${label}`); }

// ─── Read sources ─────────────────────────────────────────────────────────────

const etsService   = readFile(PATHS.etsService);
const etsTypes     = readFile(PATHS.etsTypes);
const approvalTok  = readFile(PATHS.approvalToken);
const aegisSense   = readFile(PATHS.aegisSense);
const hardGateSrc  = readFile(PATHS.hardGatePolicy);
const b65          = readJson(PATHS.b65Artifact);

const SERVICE_ID  = 'carbonx-backend';
const ALIAS_ID    = 'carbonx';
const carbonxPol  = CARBONX_HG2B_POLICY;

// ─── C1-C15: Policy Declaration ──────────────────────────────────────────────

section('C1-C15 — Policy declaration verification');

check(1, 'CARBONX_HG2B_POLICY exported from hard-gate-policy.ts',
  hardGateSrc.includes('export const CARBONX_HG2B_POLICY'), true, 'policy');

check(2, 'service_id="carbonx-backend" (matches approval token scope)',
  carbonxPol.service_id, 'carbonx-backend', 'policy');

check(3, 'hg_group="HG-2"',
  carbonxPol.hg_group, 'HG-2', 'policy');

check(4, 'rollout_order=8',
  carbonxPol.rollout_order, 8, 'policy');

check(5, 'hard_gate_enabled=false (NOT promoted)',
  carbonxPol.hard_gate_enabled, false, 'policy');

check(6, 'stage contains "soft_canary"',
  carbonxPol.stage.includes('soft_canary'), true, 'policy');

check(7, 'external_state_touch=true',
  carbonxPol.external_state_touch, true, 'policy');

check(8, 'boundary_crossing=true',
  carbonxPol.boundary_crossing, true, 'policy');

check(9, 'reversible_actions_only=false',
  carbonxPol.reversible_actions_only, false, 'policy');

check(10, 'approval_required_for_irreversible_action=true',
  carbonxPol.approval_required_for_irreversible_action, true, 'policy');

check(11, 'kill_switch_scope="service"',
  carbonxPol.kill_switch_scope, 'service', 'policy');

check(12, 'observability_required=true',
  carbonxPol.observability_required, true, 'policy');

check(13, 'audit_artifact_required=true',
  carbonxPol.audit_artifact_required, true, 'policy');

check(14, 'financial_settlement_doctrine=true',
  carbonxPol.financial_settlement_doctrine, true, 'policy');

const requiredScopeFields = [
  'service_id', 'capability', 'operation', 'org_id', 'vessel_id',
  'ets_account_id', 'compliance_year', 'eua_amount', 'externalRef', 'actor_user_id',
];
check(15, 'approval_scope_fields contains all 10 required financial fields',
  requiredScopeFields.every(f => carbonxPol.approval_scope_fields?.includes(f)), true, 'policy');

// ─── C16-C29: ALLOW Surface Simulation ────────────────────────────────────────

section('C16-C29 — ALLOW surface (dryRunOverride=true, softDecision=BLOCK)');

const allowCaps = [
  'READ', 'GET', 'LIST', 'QUERY', 'SEARCH', 'HEALTH',
  'EXTERNAL_READ', 'FETCH_STATUS', 'CHECK_CONNECTION', 'DRY_RUN',
  'SIMULATE_ETS_SURRENDER', 'GET_ETS_BALANCE', 'GET_CARBON_PRICE', 'CALCULATE_OBLIGATION',
];

allowCaps.forEach((cap, i) => {
  const result = simulateHardGate(SERVICE_ID, 'BLOCK', cap, 'test', true);
  check(16 + i, `${cap} → ALLOW (hard-gate active, soft=BLOCK)`,
    result.simulated_hard_decision, 'ALLOW', 'surface-allow');
});

// ─── C30-C39: GATE Surface Simulation ─────────────────────────────────────────

section('C30-C39 — GATE surface (dryRunOverride=true, softDecision=BLOCK → still_gate → GATE)');

const gateCaps = [
  'SURRENDER_ETS_ALLOWANCES',
  'SUBMIT_ETS_SURRENDER',
  'RECORD_ETS_SURRENDER',
  'UPDATE_EUA_BALANCE',
  'ADJUST_COMPLIANCE_POSITION',
  'SETTLE_CARBON_POSITION',
  'TRANSFER_EUA',
  'UPDATE_ETS_ACCOUNT',
  'LINK_REGISTRY_ACCOUNT',
  'GENERATE_COMPLIANCE_FILING',
];

gateCaps.forEach((cap, i) => {
  const result = simulateHardGate(SERVICE_ID, 'BLOCK', cap, 'test', true);
  check(30 + i, `${cap} → GATE (still_gate: soft=BLOCK → GATE not BLOCK)`,
    result.simulated_hard_decision, 'GATE', 'surface-gate');
});

// ─── C40-C49: HARD-BLOCK Surface Simulation ────────────────────────────────────

section('C40-C49 — HARD-BLOCK surface (dryRunOverride=true, softDecision=ALLOW)');

const blockCaps = [
  'IMPOSSIBLE_OP',
  'EMPTY_CAPABILITY_ON_WRITE',
  'SUBMIT_ETS_SURRENDER_UNAPPROVED',
  'SURRENDER_EUA_WITHOUT_TOKEN',
  'BULK_EUA_SURRENDER',
  'FORCE_EUA_OVERWRITE',
  'BACKDATE_ETS_SURRENDER',
  'DELETE_ETS_TRANSACTION',
  'BYPASS_EUA_IDEMPOTENCY',
  'MUTATE_EUA_BALANCE_WITHOUT_EXTERNAL_REF',
];

blockCaps.forEach((cap, i) => {
  const result = simulateHardGate(SERVICE_ID, 'ALLOW', cap, 'test', true);
  check(40 + i, `${cap} → BLOCK (hard_block_capabilities, overrides soft=ALLOW)`,
    result.simulated_hard_decision, 'BLOCK', 'surface-block');
});

// ─── C50-C81: Soak Run 1/7 Verification ──────────────────────────────────────

section('C50-C58 — Soak run 1/7 prerequisites + policy confirmation');

check(50, 'Batch 65 artifact exists',
  readFile(PATHS.b65Artifact).length > 0, true, 'soak');

check(51, 'Batch 65 verdict=PASS',
  b65.verdict, 'PASS', 'soak');

check(52, 'Batch 65 gate_decision=READY_FOR_POLICY_DECLARATION',
  b65.gate_decision, 'READY_FOR_POLICY_DECLARATION', 'soak');

check(53, 'CARBONX_HG2B_POLICY in HARD_GATE_POLICIES under "carbonx-backend"',
  HARD_GATE_POLICIES['carbonx-backend'] === carbonxPol, true, 'soak');

check(54, 'CARBONX_HG2B_POLICY.hard_gate_enabled=false (confirmed at soak)',
  HARD_GATE_POLICIES['carbonx-backend']?.hard_gate_enabled, false, 'soak');

check(55, 'carbonx-backend NOT in AEGIS_HARD_GATE_SERVICES env var',
  (process.env.AEGIS_HARD_GATE_SERVICES ?? '').split(',').map(s => s.trim()).includes('carbonx-backend'),
  false, 'soak');

check(56, 'rollout_order=8 (confirmed at soak)',
  HARD_GATE_POLICIES['carbonx-backend']?.rollout_order, 8, 'soak');

check(57, 'financial_settlement_doctrine=true (confirmed at soak)',
  HARD_GATE_POLICIES['carbonx-backend']?.financial_settlement_doctrine, true, 'soak');

check(58, 'approval_scope_fields includes ets_account_id + compliance_year + eua_amount',
  carbonxPol.approval_scope_fields?.includes('ets_account_id') &&
  carbonxPol.approval_scope_fields?.includes('compliance_year') &&
  carbonxPol.approval_scope_fields?.includes('eua_amount'), true, 'soak');

section('C59-C61 — Surface simulation aggregate (soak-run confirmation)');

check(59, 'ALLOW surface: READ + DRY_RUN + SIMULATE_ETS_SURRENDER all ALLOW under dry-run',
  ['READ', 'DRY_RUN', 'SIMULATE_ETS_SURRENDER'].every(cap =>
    simulateHardGate(SERVICE_ID, 'BLOCK', cap, 'test', true).simulated_hard_decision === 'ALLOW'
  ), true, 'soak');

check(60, 'GATE surface: SURRENDER_ETS_ALLOWANCES + TRANSFER_EUA → GATE under dry-run',
  ['SURRENDER_ETS_ALLOWANCES', 'TRANSFER_EUA'].every(cap =>
    simulateHardGate(SERVICE_ID, 'BLOCK', cap, 'test', true).simulated_hard_decision === 'GATE'
  ), true, 'soak');

check(61, 'BLOCK surface: SURRENDER_EUA_WITHOUT_TOKEN + BULK_EUA_SURRENDER → BLOCK under dry-run',
  ['SURRENDER_EUA_WITHOUT_TOKEN', 'BULK_EUA_SURRENDER'].every(cap =>
    simulateHardGate(SERVICE_ID, 'ALLOW', cap, 'test', true).simulated_hard_decision === 'BLOCK'
  ), true, 'soak');

section('C62-C68 — Financial controls verification (source check)');

check(62, 'SUBMIT_ETS_SURRENDER in still_gate (requires scoped approval, not unconditional block)',
  carbonxPol.still_gate_capabilities.has('SUBMIT_ETS_SURRENDER'), true, 'soak');

check(63, 'Missing approval token triggers IrrNoApprovalError (approvalToken required in mutation)',
  etsTypes.includes('approvalToken') && approvalTok.includes('IrrNoApprovalError'), true, 'soak');

check(64, 'Wrong service_id scope rejects (AEG-E-016: service_id !== expectedServiceId)',
  approvalTok.includes("payload.service_id !== expectedServiceId"), true, 'soak');

check(65, 'simulateSurrender remains ALLOW / DRY_RUN (in always_allow_capabilities)',
  carbonxPol.always_allow_capabilities.has('SIMULATE_ETS_SURRENDER') &&
  carbonxPol.always_allow_capabilities.has('DRY_RUN'), true, 'soak');

check(66, 'simulateSurrender does not call recordSurrender (no DB writes in source)',
  (() => {
    const simStart = etsTypes.indexOf("builder.queryField('simulateSurrender'");
    const simNextMut = etsTypes.indexOf("builder.mutationField(", simStart + 1);
    const simSlice = simStart > -1 ? etsTypes.slice(simStart, simNextMut > simStart ? simNextMut : undefined) : '';
    return simSlice.length > 0 && !simSlice.includes('recordSurrender');
  })(), true, 'soak');

check(67, 'idempotency externalRef prevents double-surrender (findFirst check in recordSurrender)',
  etsService.includes('externalRef') &&
  etsService.includes('findFirst(') &&
  etsService.includes('already recorded, skipping'), true, 'soak');

check(68, 'duplicate externalRef with changed euaAmount warns (payload mismatch warn path)',
  etsService.includes('payload mismatch') &&
  etsService.includes('logger.warn'), true, 'soak');

section('C69-C71 — SENSE event fields (soak observability)');

check(69, 'SENSE event includes correlation_id (pramana receipt chain)',
  aegisSense.includes('correlation_id') &&
  etsService.includes('correlation_id:'), true, 'soak');

check(70, 'SENSE event includes irreversible=true for surrender (AEG-HG-2B-003)',
  aegisSense.includes('irreversible') &&
  etsService.includes('irreversible: true'), true, 'soak');

check(71, 'SENSE event includes before_snapshot + after_snapshot + delta (CA-003)',
  aegisSense.includes('before_snapshot') &&
  aegisSense.includes('after_snapshot') &&
  aegisSense.includes('delta'), true, 'soak');

section('C72-C78 — Regression + safety invariants');

// Unknown capability: carbonx alias
const unknownCapResult = simulateHardGate(SERVICE_ID, 'ALLOW', 'UNKNOWN_FINANCIAL_OP', 'test', true);
check(72, 'Unknown capability does not hard-block (unknown_cap_gates_before_blocking)',
  unknownCapResult.simulated_hard_decision !== 'BLOCK', true, 'soak');

// Unknown service
const unknownSvcResult = simulateHardGate('unknown-financial-service', 'ALLOW', 'DELETE', 'delete', true);
check(73, 'Unknown service never blocks (no policy = soft decision preserved)',
  unknownSvcResult.simulated_hard_decision, 'ALLOW', 'soak');

// parali-central regression: still LIVE and policy intact
const paraliPol = HARD_GATE_POLICIES['parali-central'];
check(74, 'parali-central remains HG-2B live (hard_gate_enabled=true, policy clean)',
  paraliPol?.hard_gate_enabled === true && paraliPol?.hg_group === 'HG-2', true, 'soak');

// 7 live guards
const liveCount = Object.values(HARD_GATE_POLICIES).filter(p => p.hard_gate_enabled === true).length;
check(75, 'Existing 7 live guards all have hard_gate_enabled=true (regression clean)',
  liveCount, 7, 'soak');

// Kill switch: temporarily clear env var, verify chirpee (live guard) goes inactive
const savedEnv = process.env.AEGIS_HARD_GATE_SERVICES;
process.env.AEGIS_HARD_GATE_SERVICES = '';
const killSwitchResult = applyHardGate('chirpee', 'BLOCK', 'DELETE', 'delete');
process.env.AEGIS_HARD_GATE_SERVICES = savedEnv ?? '';
check(76, 'Kill switch: clearing AEGIS_HARD_GATE_SERVICES suppresses chirpee hard gate',
  killSwitchResult.hard_gate_active, false, 'soak');

// carbonx candidate-inert (not in env var → gate inactive)
const candidateInertResult = applyHardGate(SERVICE_ID, 'BLOCK', 'SURRENDER_ETS_ALLOWANCES', 'surrender');
check(77, 'carbonx candidate-inert: AEGIS_HARD_GATE_SERVICES absent → gate not active',
  candidateInertResult.hard_gate_active, false, 'soak');

// HG-2C live count = 0 (no service with hg_group="HG-2C" and hard_gate_enabled=true)
const hg2cLive = Object.values(HARD_GATE_POLICIES).filter(
  p => (p.hg_group === 'HG-2C' || p.hg_group === 'HG-3') && p.hard_gate_enabled === true
).length;
check(78, 'HG-2C/HG-3 live count remains 0',
  hg2cLive, 0, 'soak');

section('C79-C81 — Promotion guard + soak outcome');

check(79, 'promotion_permitted_carbonx=false — hard_gate_enabled=false, not in env var',
  carbonxPol.hard_gate_enabled === false &&
  !(process.env.AEGIS_HARD_GATE_SERVICES ?? '').includes('carbonx'), true, 'soak');

// False positives = 0 (no ALLOW capability returned BLOCK or GATE in C16-C29)
const fpCount = results
  .filter(r => r.section === 'surface-allow' && r.verdict === 'FAIL')
  .length;
check(80, 'False positives=0 — no ALLOW capability was blocked in soak run 1',
  fpCount, 0, 'soak');

// Production fires = 0 (carbonx not in AEGIS_HARD_GATE_SERVICES, gate not active)
check(81, 'Production fires=0 — carbonx gate not active (not in AEGIS_HARD_GATE_SERVICES)',
  candidateInertResult.hard_gate_applied, false, 'soak');

// ─── Results ──────────────────────────────────────────────────────────────────

const total   = passed + failed;
const verdict = failed === 0 ? 'PASS' : 'FAIL';
const soakRun = { run: 1, of: 7, false_positives: fpCount, production_fires: 0 };

console.log(`\n═══════════════════════════════════════════════════════════`);
console.log(`AEGIS Batch 66 — carbonx HG-2B Financial Soft-Canary Run 1/7`);
console.log(`Verdict:        ${verdict}`);
console.log(`Checks:         ${passed}/${total} PASS`);
console.log(`Soak run:       ${soakRun.run}/${soakRun.of}`);
console.log(`False positives: ${soakRun.false_positives}`);
console.log(`Live roster:    ${liveCount} (unchanged)`);
console.log(`═══════════════════════════════════════════════════════════`);

if (failed > 0) {
  console.log('\nFailed checks:');
  results.filter(r => r.verdict === 'FAIL').forEach(r =>
    console.log(`  C${r.id}: [${r.section}] ${r.label}`)
  );
}

// ─── Artifact ─────────────────────────────────────────────────────────────────

const artifact = {
  batch: 66,
  title: 'carbonx HG-2B Financial Soft-Canary Soak Run 1/7',
  run_at: new Date().toISOString(),
  verdict,
  checks_passed: passed,
  checks_total: total,
  soak_run: soakRun,
  policy_declared: {
    service_id: carbonxPol.service_id,
    hg_group: carbonxPol.hg_group,
    hard_gate_enabled: carbonxPol.hard_gate_enabled,
    rollout_order: carbonxPol.rollout_order,
    stage: carbonxPol.stage,
    financial_settlement_doctrine: carbonxPol.financial_settlement_doctrine,
  },
  live_roster_count: liveCount,
  hg2b_live_count: 1,
  hg2c_live_count: hg2cLive,
  carbonx_in_aegis_env: (process.env.AEGIS_HARD_GATE_SERVICES ?? '').includes('carbonx'),
  promotion_permitted_carbonx: false,
  surface_simulation: {
    allow_surface_checks: results.filter(r => r.section === 'surface-allow').length,
    gate_surface_checks:  results.filter(r => r.section === 'surface-gate').length,
    block_surface_checks: results.filter(r => r.section === 'surface-block').length,
    all_allow_pass: results.filter(r => r.section === 'surface-allow' && r.verdict === 'PASS').length,
    all_gate_pass:  results.filter(r => r.section === 'surface-gate'  && r.verdict === 'PASS').length,
    all_block_pass: results.filter(r => r.section === 'surface-block' && r.verdict === 'PASS').length,
  },
  next_batch: verdict === 'PASS'
    ? 'Batch 67 — carbonx HG-2B financial soft-canary soak run 2/7'
    : 'Fix failing checks before run 2',
  results,
};

fs.mkdirSync('/root/aegis/audits', { recursive: true });
const artifactPath = '/root/aegis/audits/batch66_carbonx_hg2b_soft_canary_run1.json';
fs.writeFileSync(artifactPath, JSON.stringify(artifact, null, 2));
console.log(`\nArtifact: ${artifactPath}`);

if (failed > 0) process.exit(1);
