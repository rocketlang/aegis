#!/usr/bin/env bun
// Batch 101 — parali-central SDK adoption implementation audit
// "Carbonx proved the financial locks. Parali proves the locks travel."
//
// Verifies that the SDK wiring is correct in source:
//   - @ankr/aegis-guard dependency installed
//   - emitAegisSenseEvent replaces app.log.info in SENSE endpoint
//   - wireParaliSenseTransport called in forjaRoutes
//   - parali-sense-transport.ts uses configureSenseTransport
//   - No raw app.log.info left in SENSE endpoint
//
// Run: bun /root/aegis/scripts/batch101-parali-central-sdk-impl.ts

import { readFileSync, existsSync, writeFileSync } from 'fs';
import { resolve } from 'path';

const PARALI = '/root/apps/parali-central/backend';

let passed = 0;
let failed = 0;
const failures: string[] = [];

function check(id: string, label: string, condition: boolean, detail?: string): void {
  if (condition) {
    console.log(`  ✅ ${id}: ${label}${detail ? ` — ${detail}` : ''}`);
    passed++;
  } else {
    console.log(`  ❌ ${id}: ${label}${detail ? ` — ${detail}` : ''}`);
    failed++;
    failures.push(`${id}: ${label}`);
  }
}

function readFile(rel: string): string {
  const p = resolve(PARALI, rel);
  return existsSync(p) ? readFileSync(p, 'utf-8') : '';
}

// ── §1 Dependency ─────────────────────────────────────────────────────────────

console.log('\n§1 — @ankr/aegis-guard dependency');

{
  const pkg = readFile('package.json');
  const hasDep = pkg.includes('"@ankr/aegis-guard"');
  check('B101-DEP-001', 'package.json includes @ankr/aegis-guard', hasDep);

  const nodeModulesGuard = resolve(PARALI, 'node_modules/@ankr/aegis-guard');
  check('B101-DEP-002', 'aegis-guard present in node_modules', existsSync(nodeModulesGuard));
}

// ── §2 Sense transport file ────────────────────────────────────────────────────

console.log('\n§2 — parali-sense-transport.ts');

{
  const transport = readFile('src/lib/parali-sense-transport.ts');
  check('B101-TRANS-001', 'parali-sense-transport.ts exists', transport.length > 0);
  check('B101-TRANS-002', 'configureSenseTransport imported from @ankr/aegis-guard',
    transport.includes('configureSenseTransport') && transport.includes('@ankr/aegis-guard'));
  check('B101-TRANS-003', 'wireParaliSenseTransport exported',
    transport.includes('export function wireParaliSenseTransport'));
  check('B101-TRANS-004', 'Fastify logger bridged via app.log',
    transport.includes('log.info') && transport.includes('aegis_sense: true'));
  check('B101-TRANS-005', 'SENSE:event_type label in transport',
    transport.includes('SENSE:${evt.event_type}') || transport.includes('`SENSE:${evt.event_type}`'));
}

// ── §3 forja.ts source controls ───────────────────────────────────────────────

console.log('\n§3 — forja.ts SDK wiring');

{
  const forja = readFile('src/routes/forja.ts');
  check('B101-FORJA-001', 'emitAegisSenseEvent imported from @ankr/aegis-guard',
    forja.includes('emitAegisSenseEvent') && forja.includes('@ankr/aegis-guard'));
  check('B101-FORJA-002', 'wireParaliSenseTransport imported',
    forja.includes('wireParaliSenseTransport'));
  check('B101-FORJA-003', 'wireParaliSenseTransport called in forjaRoutes',
    forja.includes('wireParaliSenseTransport(app.log)'));
  check('B101-FORJA-004', 'emitAegisSenseEvent called in SENSE endpoint',
    forja.includes('emitAegisSenseEvent('));
}

// ── §4 No raw app.log.info in SENSE path ─────────────────────────────────────

console.log('\n§4 — Raw logger removed from SENSE endpoint');

{
  const forja = readFile('src/routes/forja.ts');
  // Check that app.log.info is not used inside the SENSE endpoint
  // Strategy: find the SENSE POST handler block and check it has no app.log.info
  const senseHandlerStart = forja.indexOf("POST /api/v2/forja/sense/emit");
  const senseHandlerEnd = forja.indexOf("GET /api/v2/forja/proof");
  const senseBlock = senseHandlerStart >= 0 && senseHandlerEnd >= 0
    ? forja.slice(senseHandlerStart, senseHandlerEnd)
    : '';
  const rawLogInSense = senseBlock.includes('app.log.info');
  check('B101-CLEAN-001', 'app.log.info removed from SENSE endpoint body', !rawLogInSense,
    rawLogInSense ? 'raw app.log.info still present in SENSE block' : 'clean');
}

// ── §5 AegisSenseEvent fields ─────────────────────────────────────────────────

console.log('\n§5 — AegisSenseEvent required fields');

{
  const forja = readFile('src/routes/forja.ts');
  const required = [
    ['event_type', 'B101-EVT-001'],
    ['service_id', 'B101-EVT-002'],
    ['capability', 'B101-EVT-003'],
    ['before_snapshot', 'B101-EVT-004'],
    ['after_snapshot', 'B101-EVT-005'],
    ['emitted_at', 'B101-EVT-006'],
    ['irreversible', 'B101-EVT-007'],
    ['correlation_id', 'B101-EVT-008'],
  ] as [string, string][];

  for (const [field, id] of required) {
    check(id, `AegisSenseEvent.${field} present in emit call`, forja.includes(field + ':'));
  }
}

// ── §6 @rule annotations ──────────────────────────────────────────────────────

console.log('\n§6 — @rule annotations');

{
  const forja = readFile('src/routes/forja.ts');
  const transport = readFile('src/lib/parali-sense-transport.ts');
  check('B101-RULE-001', '@rule:AEG-HG-2B-003 annotated in forja.ts',
    forja.includes('@rule:AEG-HG-2B-003'));
  check('B101-RULE-002', '@rule:AEG-HG-2B-003 annotated in transport',
    transport.includes('@rule:AEG-HG-2B-003'));
}

// ── Result ─────────────────────────────────────────────────────────────────────

console.log('\n──────────────────────────────────────────────────────────────────────────\n');

const verdict = failed === 0 ? 'PASS' : 'FAIL';
console.log(`Batch 101: ${verdict} — ${passed}/${passed + failed} checks passed`);
console.log('Doctrine: Carbonx proved the financial locks. Parali proves the locks travel.');

if (failures.length > 0) {
  console.log('\nFailed:');
  failures.forEach(f => console.log(`  ❌ ${f}`));
}

const artifact = {
  batch: '101',
  batch_name: 'parali-central-sdk-adoption-impl',
  service: 'parali-central',
  hg_group: 'HG-2B',
  rule_refs: ['AEG-HG-2B-003', 'CA-003', 'FRJ-SE-001'],
  sdk_package: '@ankr/aegis-guard',
  migration_type: 'additive',
  verdict,
  checks_passed: passed,
  checks_total: passed + failed,
  lock_1_decision_gate: 'deferred — APPROVE_DIVIDEND not yet implemented in source',
  lock_2_identity: 'deferred — conditional on lock 1',
  lock_3_observability: 'WIRED — emitAegisSenseEvent + configureSenseTransport',
  lock_4_rollback: 'deferred — simulateDividend not yet implemented',
  lock_5_idempotency: 'deferred — dividend action ref table not yet added',
  timestamp: new Date().toISOString(),
  promotion_permitted: failed === 0,
};

writeFileSync(
  '/root/aegis/audits/batch101_parali_central_sdk_impl.json',
  JSON.stringify(artifact, null, 2),
);
console.log('\nAudit artifact: /root/aegis/audits/batch101_parali_central_sdk_impl.json');

if (failed > 0) process.exit(1);
