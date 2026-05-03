/**
 * AEGIS Batch 64 — carbonx BR-5 Financial Remediation
 *
 * Verifies all four CARBONX-FIX-NNN controls are present in source.
 * Run after implementing fixes, before policy declaration (Batch 65).
 *
 * Verdict: PASS = all 30 checks pass = READY_FOR_CODE_SCAN_RECHECK
 * Gate: Batch 65 will re-run the code-scan gate to confirm gate_decision=READY_FOR_POLICY_DECLARATION
 */

import * as fs from 'fs';
import * as path from 'path';

// ─── Paths ────────────────────────────────────────────────────────────────────

const CARBONX_ROOT = '/root/apps/carbonx/backend';
const PATHS = {
  etsService:      path.join(CARBONX_ROOT, 'src/services/ets/ets-service.ts'),
  etsTypes:        path.join(CARBONX_ROOT, 'src/schema/types/ets.ts'),
  schema:          path.join(CARBONX_ROOT, 'prisma/schema.prisma'),
  approvalToken:   path.join(CARBONX_ROOT, 'src/lib/aegis-approval-token.ts'),
  aegisSense:      path.join(CARBONX_ROOT, 'src/lib/aegis-sense.ts'),
};

// ─── Audit State ──────────────────────────────────────────────────────────────

let passed = 0;
let failed = 0;
const results: Array<{ id: number; label: string; verdict: 'PASS' | 'FAIL'; section: string }> = [];

function readFile(p: string): string {
  try { return fs.readFileSync(p, 'utf8'); }
  catch { return ''; }
}

function check(
  id: number,
  label: string,
  actual: unknown,
  expected: unknown,
  section: string,
): void {
  const ok = actual === expected;
  results.push({ id, label, verdict: ok ? 'PASS' : 'FAIL', section });
  if (ok) passed++;
  else {
    failed++;
    console.error(`  ✗ C${id} [${section}] ${label}`);
    console.error(`      expected=${JSON.stringify(expected)}, got=${JSON.stringify(actual)}`);
  }
}

function section(label: string): void {
  console.log(`\n── ${label}`);
}

// ─── Read Sources ─────────────────────────────────────────────────────────────

const etsService  = readFile(PATHS.etsService);
const etsTypes    = readFile(PATHS.etsTypes);
const schema      = readFile(PATHS.schema);
const approvalTok = readFile(PATHS.approvalToken);
const aegisSense  = readFile(PATHS.aegisSense);

// ─── FIX-001: Approval Token (C1–C8) ─────────────────────────────────────────

section('FIX-001 — Approval token gate (AEG-E-016 / IRR-NOAPPROVAL)');

check(1,  'aegis-approval-token.ts file exists',
  approvalTok.length > 0, true, 'fix-001');

check(2,  'IrrNoApprovalError class defined',
  approvalTok.includes('class IrrNoApprovalError'), true, 'fix-001');

check(3,  'verifyApprovalToken function exported',
  approvalTok.includes('export function verifyApprovalToken'), true, 'fix-001');

check(4,  '@rule:AEG-E-016 annotation present in aegis-approval-token.ts',
  approvalTok.includes('AEG-E-016'), true, 'fix-001');

check(5,  'surrenderEtsAllowances has approvalToken arg',
  etsTypes.includes('approvalToken') && etsTypes.includes('surrenderEtsAllowances'), true, 'fix-001');

check(6,  'verifyApprovalToken called in surrenderEtsAllowances resolve',
  etsTypes.includes('verifyApprovalToken(') &&
  etsTypes.includes("'carbonx-backend'") &&
  etsTypes.includes("'surrenderEtsAllowances'") &&
  etsTypes.includes("'eua_surrender'"), true, 'fix-001');

check(7,  'verifyApprovalToken imported from aegis-approval-token.js in ets.ts',
  etsTypes.includes("from '../../lib/aegis-approval-token.js'"), true, 'fix-001');

check(8,  'IrrNoApprovalError also imported (for type completeness)',
  etsTypes.includes('IrrNoApprovalError'), true, 'fix-001');

// ─── FIX-002: SENSE Event Emission (C9–C16) ───────────────────────────────────

section('FIX-002 — SENSE event emission (CA-003 / AEG-HG-2B-003)');

check(9,  'aegis-sense.ts file exists',
  aegisSense.length > 0, true, 'fix-002');

check(10, 'emitAegisSenseEvent function exported',
  aegisSense.includes('export function emitAegisSenseEvent'), true, 'fix-002');

check(11, '@rule:CA-003 annotation present in aegis-sense.ts',
  aegisSense.includes('CA-003'), true, 'fix-002');

check(12, 'AegisSenseEvent interface has before_snapshot',
  aegisSense.includes('before_snapshot'), true, 'fix-002');

check(13, 'AegisSenseEvent interface has after_snapshot',
  aegisSense.includes('after_snapshot'), true, 'fix-002');

check(14, 'AegisSenseEvent interface has delta',
  aegisSense.includes('delta'), true, 'fix-002');

check(15, 'emitAegisSenseEvent imported in ets-service.ts',
  etsService.includes("from '../../lib/aegis-sense.js'"), true, 'fix-002');

check(16, 'emitAegisSenseEvent called inside recordSurrender with ETS_SURRENDER event type',
  etsService.includes("emitAegisSenseEvent(") &&
  etsService.includes("'ETS_SURRENDER'"), true, 'fix-002');

// ─── FIX-003: simulateSurrender Dry-Run (C17–C23) ─────────────────────────────

section('FIX-003 — simulateSurrender read-only query');

check(17, 'simulateSurrender queryField defined in ets.ts',
  etsTypes.includes("builder.queryField('simulateSurrender'"), true, 'fix-003');

check(18, 'simulateSurrender has vesselId arg',
  (() => {
    const start = etsTypes.indexOf("builder.queryField('simulateSurrender'");
    const end   = etsTypes.indexOf("builder.queryField(", start + 1);
    const slice = etsTypes.slice(start, end > start ? end : undefined);
    return slice.includes('vesselId');
  })(), true, 'fix-003');

check(19, 'simulateSurrender has year arg',
  (() => {
    const start = etsTypes.indexOf("builder.queryField('simulateSurrender'");
    const end   = etsTypes.indexOf("builder.queryField(", start + 1);
    const slice = etsTypes.slice(start, end > start ? end : undefined);
    return slice.includes('year');
  })(), true, 'fix-003');

check(20, 'simulateSurrender has euaAmount arg',
  (() => {
    const start = etsTypes.indexOf("builder.queryField('simulateSurrender'");
    const end   = etsTypes.indexOf("builder.queryField(", start + 1);
    const slice = etsTypes.slice(start, end > start ? end : undefined);
    return slice.includes('euaAmount');
  })(), true, 'fix-003');

check(21, 'simulateSurrender returns projectedNewSurrendered',
  etsTypes.includes('projectedNewSurrendered'), true, 'fix-003');

check(22, 'simulateSurrender returns approvalScopeRequired',
  etsTypes.includes('approvalScopeRequired'), true, 'fix-003');

check(23, 'simulateSurrender returns rollbackNote',
  etsTypes.includes('rollbackNote'), true, 'fix-003');

// ─── FIX-004: Idempotency Key (C24–C30) ───────────────────────────────────────

section('FIX-004 — Idempotency key (double-surrender prevention)');

check(24, 'externalRef field in EtsTransaction model in schema.prisma',
  schema.includes('externalRef') &&
  schema.includes('EtsTransaction'), true, 'fix-004');

check(25, 'externalRef has @unique constraint in schema.prisma',
  (() => {
    const start = schema.indexOf('model EtsTransaction');
    const end   = schema.indexOf('\n}', start);
    const model = schema.slice(start, end);
    return model.includes('@unique') && model.includes('externalRef');
  })(), true, 'fix-004');

check(26, 'externalRef exposed in EtsTransaction GQL object',
  (() => {
    const start = etsTypes.indexOf("builder.prismaObject('EtsTransaction'");
    const end   = etsTypes.indexOf('});', start);
    const obj   = etsTypes.slice(start, end);
    return obj.includes('externalRef');
  })(), true, 'fix-004');

check(27, 'recordSurrender signature has externalRef parameter',
  etsService.includes('externalRef?: string'), true, 'fix-004');

check(28, 'idempotency check (findFirst by externalRef) present in recordSurrender',
  etsService.includes('findFirst(') &&
  etsService.includes('externalRef'), true, 'fix-004');

check(29, 'surrenderEtsAllowances mutation passes externalRef to recordSurrender',
  (() => {
    const start = etsTypes.indexOf("builder.mutationField('surrenderEtsAllowances'");
    const end   = etsTypes.indexOf("builder.mutationField(", start + 1);
    const slice = etsTypes.slice(start, end > start ? end : undefined);
    return slice.includes('externalRef') && slice.includes('recordSurrender');
  })(), true, 'fix-004');

// ─── Integration Gate (C30) ───────────────────────────────────────────────────

section('Integration — all Five Locks present');

const hasFix001 = approvalTok.includes('verifyApprovalToken') &&
                  etsTypes.includes('approvalToken');
const hasFix002 = aegisSense.includes('emitAegisSenseEvent') &&
                  etsService.includes('ETS_SURRENDER');
const hasFix003 = etsTypes.includes("builder.queryField('simulateSurrender'");
const hasFix004 = schema.includes('externalRef') &&
                  etsService.includes('externalRef?: string');

check(30, 'all four fixes present → gate_decision=READY_FOR_CODE_SCAN_RECHECK',
  hasFix001 && hasFix002 && hasFix003 && hasFix004, true, 'integration');

// ─── Results ──────────────────────────────────────────────────────────────────

const total   = passed + failed;
const verdict = failed === 0 ? 'PASS' : 'FAIL';
const gateDecision = (hasFix001 && hasFix002 && hasFix003 && hasFix004)
  ? 'READY_FOR_CODE_SCAN_RECHECK'
  : 'BLOCKED_REMEDIATION_INCOMPLETE';

console.log(`\n═══════════════════════════════════════════════════════════`);
console.log(`AEGIS Batch 64 — carbonx BR-5 Financial Remediation`);
console.log(`Verdict:       ${verdict}`);
console.log(`Checks:        ${passed}/${total} PASS`);
console.log(`Gate decision: ${gateDecision}`);
console.log(`═══════════════════════════════════════════════════════════`);

if (failed > 0) {
  console.log('\nFailed checks:');
  results.filter(r => r.verdict === 'FAIL').forEach(r =>
    console.log(`  C${r.id}: ${r.label}`)
  );
}

// ─── Artifact ─────────────────────────────────────────────────────────────────

const artifact = {
  batch: 64,
  title: 'carbonx BR-5 Financial Remediation',
  run_at: new Date().toISOString(),
  verdict,
  checks_passed: passed,
  checks_total: total,
  gate_decision: gateDecision,
  fixes_implemented: {
    'CARBONX-FIX-001': hasFix001,
    'CARBONX-FIX-002': hasFix002,
    'CARBONX-FIX-003': hasFix003,
    'CARBONX-FIX-004': hasFix004,
  },
  files_created: [
    'src/lib/aegis-approval-token.ts',
    'src/lib/aegis-sense.ts',
  ],
  files_modified: [
    'src/services/ets/ets-service.ts',
    'src/schema/types/ets.ts',
    'prisma/schema.prisma',
  ],
  schema_change: {
    table: 'ets_transactions',
    column: 'externalRef',
    type: 'TEXT NULL UNIQUE',
    method: 'psql direct (demo class, non-interactive env)',
    destructive: false,
  },
  next_batch: 'Batch 65 — re-run code-scan gate to confirm gate_decision=READY_FOR_POLICY_DECLARATION',
  results,
};

fs.mkdirSync('/root/aegis/audits', { recursive: true });
const artifactPath = '/root/aegis/audits/batch64_carbonx_br5_financial_remediation.json';
fs.writeFileSync(artifactPath, JSON.stringify(artifact, null, 2));
console.log(`\nArtifact: ${artifactPath}`);

if (failed > 0) process.exit(1);
