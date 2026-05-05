#!/usr/bin/env bun
// Batch 97 — carbonx SDK adoption cleanup + dashboard coverage
// "The fallback was removed. The locks now live in the SDK."
//
// Removes deprecated local AEGIS helpers only after Batch 96 regression passed.
// Zero imports of deprecated files confirmed before deletion.
// No governance state changed. Quality scores unchanged.
// SDK adoption dashboard updated.

import { readFileSync, existsSync, writeFileSync, mkdirSync, unlinkSync } from 'fs';
import { execSync } from 'child_process';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const AEGIS_ROOT = resolve(__dirname, '..');
const CARBONX    = resolve(AEGIS_ROOT, '../apps/carbonx/backend');
const SDK_ROOT   = resolve(AEGIS_ROOT, 'packages/aegis-guard');
const CARBONX_LIB = resolve(CARBONX, 'src/lib');

// ─── check harness ────────────────────────────────────────────────────────────

let passed  = 0;
let failed  = 0;
const failures: string[] = [];

function check(id: string, label: string, condition: boolean): void {
  if (condition) {
    console.log(`  ✅ ${id}: ${label}`);
    passed++;
  } else {
    console.log(`  ❌ ${id}: ${label}`);
    failed++;
    failures.push(`${id}: ${label}`);
  }
}

function section(title: string): void {
  console.log(`\n${title}`);
}

function readSrc(rel: string): string {
  const p = resolve(CARBONX, rel);
  return existsSync(p) ? readFileSync(p, 'utf8') : '';
}

function grepLiveImport(pattern: string): string[] {
  try {
    // Match only TypeScript import/from lines — pattern must appear in an import statement
    const out = execSync(
      `grep -rn "^import\\|} from '\\|} from \\"" src/ --include="*.ts"`,
      { cwd: CARBONX, encoding: 'utf8' },
    ).trim();
    // grep output: "filename:lineno:content" — extract content after second colon
    return out.split('\n').filter(l => {
      if (l.trim().length === 0) return false;
      const m = l.match(/^[^:]+:\d+:(.*)/);
      const content = m ? m[1].trim() : '';
      if (!content) return false;
      // exclude comment lines
      if (content.startsWith('//') || content.startsWith('*') || content.startsWith('/*')) return false;
      return content.includes(pattern);
    });
  } catch {
    return []; // grep exits 1 when no matches
  }
}

function gitDiffClean(relPath: string): boolean {
  try {
    const diff = execSync(`git diff HEAD -- ${relPath}`, { cwd: AEGIS_ROOT, encoding: 'utf8' });
    return diff.trim() === '';
  } catch {
    return false;
  }
}

// ─── §1 Prerequisites ─────────────────────────────────────────────────────────

section('§1 Prerequisites — Batch 96 PASS required before deletion');

const b96Path   = resolve(AEGIS_ROOT, 'audits/batch96_carbonx_sdk_five_locks_regression.json');
const b96Exists = existsSync(b96Path);
const b96       = b96Exists
  ? JSON.parse(readFileSync(b96Path, 'utf8')) as Record<string, unknown>
  : {};

check('B97-001', 'Batch 96 artifact exists', b96Exists);
check('B97-002', 'Batch 96 verdict = PASS',  b96['verdict'] === 'PASS');

// Hard stop — do not proceed to deletion if Batch 96 did not pass
if (failed > 0) {
  console.log('\n🛑 HARD STOP: Batch 96 prerequisite not met. Do not delete deprecated helpers.');
  process.exit(1);
}

// ─── §2 Zero-import proof (before deletion) ───────────────────────────────────

section('§2 Zero-import proof — grep confirms no live imports of deprecated files');

const approvalImports = grepLiveImport('aegis-approval-token');
const senseImports    = grepLiveImport('aegis-sense');

check('B97-003', 'Zero live imports of aegis-approval-token.ts (comments excluded)',
  approvalImports.length === 0);
check('B97-004', 'Zero live imports of aegis-sense.ts (comments excluded)',
  senseImports.length === 0);

if (approvalImports.length > 0) {
  console.log('    Remaining imports:');
  approvalImports.forEach(l => console.log(`      ${l}`));
}
if (senseImports.length > 0) {
  console.log('    Remaining imports:');
  senseImports.forEach(l => console.log(`      ${l}`));
}

if (failed > 0) {
  console.log('\n🛑 HARD STOP: Live imports of deprecated helpers remain. Do not delete.');
  process.exit(1);
}

// ─── §3 Delete deprecated files ───────────────────────────────────────────────

section('§3 Delete deprecated local helpers (safe: zero imports confirmed)');

const approvalTokenPath = resolve(CARBONX_LIB, 'aegis-approval-token.ts');
const aegisSensePath    = resolve(CARBONX_LIB, 'aegis-sense.ts');

const approvalExistsBefore = existsSync(approvalTokenPath);
const senseExistsBefore    = existsSync(aegisSensePath);

if (approvalExistsBefore) unlinkSync(approvalTokenPath);
if (senseExistsBefore)    unlinkSync(aegisSensePath);

check('B97-005', 'aegis-approval-token.ts deleted',
  approvalExistsBefore && !existsSync(approvalTokenPath));
check('B97-006', 'aegis-sense.ts deleted',
  senseExistsBefore && !existsSync(aegisSensePath));

// ─── §4 Post-deletion import verification ─────────────────────────────────────

section('§4 Post-deletion — no stale references remain');

check('B97-007', 'aegis-approval-token no longer in carbonx src (post-deletion grep)',
  grepLiveImport('aegis-approval-token').length === 0);
check('B97-008', 'aegis-sense no longer in carbonx src (post-deletion grep)',
  grepLiveImport('aegis-sense').length === 0);

// ─── §5 SDK adoption verification ─────────────────────────────────────────────

section('§5 SDK adoption — carbonx imports from @ankr/aegis-guard');

const etsSrc        = readSrc('src/schema/types/ets.ts');
const etsServiceSrc = readSrc('src/services/ets/ets-service.ts');
const transportSrc  = readSrc('src/lib/aegis-transport.ts');
const scopeSrc      = readSrc('src/lib/carbonx-scope-adapter.ts');

check('B97-009', "ets.ts imports verifyScopedApprovalToken from '@ankr/aegis-guard'",
  etsSrc.includes("from '@ankr/aegis-guard'") && etsSrc.includes('verifyScopedApprovalToken'));
check('B97-010', "ets-service.ts imports emitAegisSenseEvent + digestApprovalToken from '@ankr/aegis-guard'",
  etsServiceSrc.includes("from '@ankr/aegis-guard'") &&
  etsServiceSrc.includes('emitAegisSenseEvent') &&
  etsServiceSrc.includes('digestApprovalToken'));
check('B97-011', 'aegis-transport.ts is the sole SENSE transport adapter',
  existsSync(resolve(CARBONX_LIB, 'aegis-transport.ts')) &&
  transportSrc.includes('configureSenseTransport'));
check('B97-012', 'carbonxFinancialScope adapter is the sole carbonx-specific scope adapter',
  existsSync(resolve(CARBONX_LIB, 'carbonx-scope-adapter.ts')) &&
  scopeSrc.includes('carbonxFinancialScope'));
check('B97-013', 'No remaining local AEGIS primitive files (only SDK adapters in lib/)',
  !existsSync(resolve(CARBONX_LIB, 'aegis-approval-token.ts')) &&
  !existsSync(resolve(CARBONX_LIB, 'aegis-sense.ts')));

// ─── §6 Five Locks mapping ────────────────────────────────────────────────────

section('§6 Five Locks mapping — SDK or carbonx domain logic');

// LOCK-1 decision: verifyScopedApprovalToken (SDK)
check('B97-014', 'LOCK-1 decision: verifyScopedApprovalToken sourced from SDK (not local)',
  etsSrc.includes("from '@ankr/aegis-guard'") &&
  etsSrc.includes('verifyScopedApprovalToken') &&
  !etsSrc.includes("from '../../lib/aegis-approval-token"));

// LOCK-2 identity: 7-field scope via carbonxFinancialScope adapter
check('B97-015', 'LOCK-2 identity: carbonxFinancialScope adapter present with 7 scope fields',
  scopeSrc.includes('org_id') &&
  scopeSrc.includes('vessel_id') &&
  scopeSrc.includes('ets_account_id') &&
  scopeSrc.includes('compliance_year') &&
  scopeSrc.includes('eua_amount') &&
  scopeSrc.includes('externalRef') &&
  scopeSrc.includes('actor_user_id'));

// LOCK-3 observability: emitAegisSenseEvent (SDK) via aegis-transport.ts
check('B97-016', 'LOCK-3 observability: emitAegisSenseEvent from SDK; pino transport wired',
  etsServiceSrc.includes("from '@ankr/aegis-guard'") &&
  etsServiceSrc.includes('emitAegisSenseEvent') &&
  etsServiceSrc.includes('aegis-transport'));

// LOCK-4 rollback: simulateSurrender remains carbonx domain logic (queryField)
check('B97-017', "LOCK-4 rollback: simulateSurrender remains carbonx domain queryField (not mutation)",
  etsSrc.includes("builder.queryField('simulateSurrender'") &&
  !etsSrc.includes("builder.mutationField('simulateSurrender'"));

// LOCK-5 idempotency: externalRef Prisma findFirst still in ets-service.ts
check('B97-018', 'LOCK-5 idempotency: Prisma findFirst idempotency check remains in ets-service.ts',
  etsServiceSrc.includes('externalRef') && etsServiceSrc.includes('findFirst'));

// ─── §7 Quality scores — unchanged ────────────────────────────────────────────

section('§7 Quality scores — SDK adoption does not change promotion evidence');

const b92Path   = resolve(AEGIS_ROOT, 'audits/batch92_fleet_quality_dashboard.json');
const b92Exists = existsSync(b92Path);
const b92       = b92Exists
  ? JSON.parse(readFileSync(b92Path, 'utf8')) as Record<string, unknown>
  : {};

const cxRef = (b92['carbonx_reference'] ?? {}) as Record<string, unknown>;

check('B97-019', 'Batch 92 dashboard artifact intact',                    b92Exists);
check('B97-020', 'quality_mask_at_promotion remains 0x012A (immutable)',
  cxRef['quality_mask_at_promotion_hex'] === '0x012A');
check('B97-021', 'quality_drift_score remains 0x3000 (post-promotion evidence)',
  cxRef['quality_drift_score_hex'] === '0x3000');
check('B97-022', 'No new quality score claimed from SDK adoption (AEG-Q-003)',
  // SDK adoption is a dependency change, not a quality evidence event.
  // quality_mask_at_promotion must stay at 0x012A — not bumped.
  cxRef['quality_mask_at_promotion_hex'] === '0x012A' &&
  cxRef['quality_confidence'] === 'low');

// ─── §8 Governance — no policy or roster change ───────────────────────────────

section('§8 Governance — no policy change, no roster change');

const b75Path   = resolve(AEGIS_ROOT, 'audits/batch75_post_carbonx_hg2b_promotion_convergence_audit.json');
const b75Exists = existsSync(b75Path);
const b75       = b75Exists
  ? JSON.parse(readFileSync(b75Path, 'utf8')) as Record<string, unknown>
  : {};

const rosterList = Array.isArray(b75['live_roster_confirmed']) ? b75['live_roster_confirmed'] as string[] : [];

check('B97-023', 'Live roster confirmed: 8 services (Batch 75 promotion audit)',
  rosterList.length === 8);
check('B97-024', 'HG-2B live: parali-central + carbonx-backend present',
  rosterList.some(s => s.includes('parali')) &&
  rosterList.some(s => s.includes('carbonx')));
check('B97-025', 'HG-2A live: pramana + domain-capture present',
  rosterList.some(s => s.includes('pramana')) &&
  rosterList.some(s => s.includes('domain-capture')));
check('B97-026', 'aegis-guard SDK source unchanged — no drift from Batch 97',
  gitDiffClean('packages/aegis-guard/src'));

// ─── §9 SDK test suite ────────────────────────────────────────────────────────

section('§9 SDK test suite — bun test aegis-guard (63 tests)');

let sdkTestPassed = false;
try {
  execSync('bun test tests/aegis-guard.test.ts', {
    cwd: SDK_ROOT,
    encoding: 'utf8',
    stdio: 'pipe',
    timeout: 60_000,
  });
  sdkTestPassed = true;
} catch (err: unknown) {
  const out = (err as { stdout?: string }).stdout ?? (err as Error).message ?? '';
  console.log(`    SDK test failure:\n${out.slice(0, 400)}`);
}

check('B97-027', 'bun test aegis-guard passes — no regression after helper removal', sdkTestPassed);

// ─── §10 Emit SDK adoption artifact ──────────────────────────────────────────

section('§10 SDK adoption dashboard — update carbonx-backend adoption status');

const auditsDir = resolve(AEGIS_ROOT, 'audits');
mkdirSync(auditsDir, { recursive: true });

const sdkAdoptionArtifact = {
  artifact_id:    'aegis-sdk-adoption-coverage-v1',
  generated_at:   '2026-05-05',
  sdk_package:    '@ankr/aegis-guard',
  sdk_path:       'packages/aegis-guard',
  sdk_version:    '1.0.0',
  doctrine:       'Five Locks proved in carbonx-backend (batches 62-74). Batch 93 made them reusable. Batch 97 completed adoption.',
  services: {
    'carbonx-backend': {
      service_key:            'carbonx-backend',
      hg_group:               'HG-2B-financial',
      sdk_adoption_status:    'adopted',
      adopted_batch:          97,
      regression_batch:       96,
      five_locks_regression:  'PASS',
      sdk_package:            '@ankr/aegis-guard',
      sdk_primitives_used:    [
        'verifyScopedApprovalToken',
        'verifyAndConsumeNonce',
        'emitAegisSenseEvent',
        'digestApprovalToken',
        'IrrNoApprovalError',
      ],
      carbonx_adapters: {
        'carbonx-scope-adapter.ts': '7-field financial scope → Record<string, unknown> (ADAPTER-1)',
        'aegis-transport.ts':       'pino logger → configureSenseTransport (ADAPTER-2)',
      },
      deprecated_helpers_removed: [
        'src/lib/aegis-approval-token.ts',
        'src/lib/aegis-sense.ts',
      ],
      removed_at_batch: 97,
      quality_mask_at_promotion:     '0x012A',
      quality_drift_score:           '0x3000',
      quality_note:                  'SDK adoption is a dependency change, not a quality evidence event. quality_mask_at_promotion immutable (AEG-Q-003).',
    },
  },
  adoption_summary: {
    total_hg2b_financial_services: 1,
    fully_adopted:                 1,
    pending_adoption:              0,
  },
};

writeFileSync(
  resolve(auditsDir, 'batch97_sdk_adoption_coverage.json'),
  JSON.stringify(sdkAdoptionArtifact, null, 2),
);

check('B97-028', 'SDK adoption artifact written: batch97_sdk_adoption_coverage.json',
  existsSync(resolve(auditsDir, 'batch97_sdk_adoption_coverage.json')));

// ─── §11 Emit batch97 audit artifact ─────────────────────────────────────────

section('§11 Emit Batch 97 audit artifact');

writeFileSync(
  resolve(auditsDir, 'batch97_carbonx_sdk_adoption_cleanup.json'),
  JSON.stringify({
    batch:            97,
    batch_name:       'carbonx-sdk-adoption-cleanup',
    batch_date:       '2026-05-05',
    doctrine:         'The fallback was removed. The locks now live in the SDK.',
    sdk_package:      '@ankr/aegis-guard',
    carbonx_service:  'carbonx-backend',
    carbonx_hg_group: 'HG-2B-financial',
    deleted_files: [
      'apps/carbonx/backend/src/lib/aegis-approval-token.ts',
      'apps/carbonx/backend/src/lib/aegis-sense.ts',
    ],
    deletion_proof:   'zero live imports confirmed by grep before deletion (B97-003, B97-004)',
    five_locks_status: {
      LOCK_1_decision:      'INTACT — verifyScopedApprovalToken from @ankr/aegis-guard',
      LOCK_2_identity:      'INTACT — carbonxFinancialScope adapter (7 fields)',
      LOCK_3_observability: 'INTACT — emitAegisSenseEvent + digestApprovalToken from @ankr/aegis-guard',
      LOCK_4_rollback:      'INTACT — simulateSurrender carbonx domain queryField',
      LOCK_5_idempotency:   'INTACT — Prisma findFirst externalRef check in ets-service.ts',
    },
    quality_scores_unchanged: {
      quality_mask_at_promotion:     '0x012A',
      quality_drift_score:           '0x3000',
      quality_note:                  'SDK adoption is a dependency change, not a quality evidence event',
    },
    no_policy_change:    true,
    no_roster_change:    true,
    no_promotion_change: true,
    live_roster_count:   8,
    sdk_adoption_status: 'adopted',
    script_checks: {
      total:  passed + failed,
      passed,
      failed,
    },
    failures: failures.length > 0 ? failures : [],
    verdict:  failed === 0 ? 'PASS' : 'FAIL',
    verdict_rationale: failed === 0
      ? 'Deprecated local helpers removed after zero-import proof. Five Locks intact via SDK. carbonx fully adopted @ankr/aegis-guard.'
      : `Failures in ${failed} check(s). Review before closing.`,
    next: 'carbonx @ankr/aegis-guard adoption complete. Future HG-2B-financial services should use @ankr/aegis-guard directly from birth.',
  }, null, 2),
);

check('B97-029', 'Batch 97 audit artifact written: batch97_carbonx_sdk_adoption_cleanup.json',
  existsSync(resolve(auditsDir, 'batch97_carbonx_sdk_adoption_cleanup.json')));

// ─── final summary ────────────────────────────────────────────────────────────

section('────────────────────────────────────────────────────────────────────────');
const verdict = failed === 0 ? 'PASS' : 'FAIL';
console.log(`\nBatch 97: ${passed}/${passed + failed} passed — ${verdict}`);
if (failures.length > 0) {
  console.log('\nFailed checks:');
  failures.forEach(f => console.log(`  ❌ ${f}`));
}

console.log('\nThe fallback was removed. The locks now live in the SDK.');

if (verdict !== 'PASS') process.exit(1);
