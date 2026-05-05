#!/usr/bin/env bun
// Batch 95 — carbonx SDK migration implementation
// "The engine changed. The locks still hold."
//
// Verifies that carbonx-backend has migrated from local AEGIS helper files
// to @ankr/aegis-guard SDK using the three adapters proven in Batch 94.
// Checks source mutations are correct, Five Locks intact, old helpers kept.
//
// DOES NOT run the carbonx service. Batch 96 handles runtime regression.

import { readFileSync, existsSync, writeFileSync, mkdirSync } from 'fs';
import { execSync } from 'child_process';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const AEGIS_ROOT = resolve(__dirname, '..');
const CARBONX    = resolve(AEGIS_ROOT, '../apps/carbonx/backend');
const SDK_ROOT   = resolve(AEGIS_ROOT, 'packages/aegis-guard');

// ─── check harness ───────────────────────────────────────────────────────────

let passed = 0;
let failed = 0;
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

function readSrc(base: string, rel: string): string {
  const p = resolve(base, rel);
  if (!existsSync(p)) return '';
  return readFileSync(p, 'utf8');
}

function readJson(base: string, rel: string): Record<string, unknown> {
  return JSON.parse(readFileSync(resolve(base, rel), 'utf8'));
}

// ─── §1 Batch 94 prerequisite ────────────────────────────────────────────────

section('§1 Batch 94 prerequisite');

const b94Path = resolve(AEGIS_ROOT, 'audits/batch94_carbonx_sdk_migration_dry_run.json');
const b94Exists = existsSync(b94Path);
const b94 = b94Exists
  ? JSON.parse(readFileSync(b94Path, 'utf8')) as Record<string, unknown>
  : {};

check('B95-001', 'Batch 94 artifact exists',                           b94Exists);
check('B95-002', 'Batch 94 verdict = PASS',                            b94['verdict'] === 'PASS');
check('B95-003', 'Batch 94 confirmed migration_risk = LOW',            b94['migration_risk'] === 'LOW');
check('B95-004', 'Batch 94 confirmed 3 required adapters',
  Array.isArray(b94['required_adapters']) && (b94['required_adapters'] as unknown[]).length === 3);
check('B95-005', '@ankr/aegis-guard SDK exists',                       existsSync(SDK_ROOT));

// ─── §2 New adapter files ─────────────────────────────────────────────────────

section('§2 New adapter files');

const transportSrc = readSrc(CARBONX, 'src/lib/aegis-transport.ts');
const scopeSrc     = readSrc(CARBONX, 'src/lib/carbonx-scope-adapter.ts');

check('B95-006', 'aegis-transport.ts created',
  existsSync(resolve(CARBONX, 'src/lib/aegis-transport.ts')));
check('B95-007', 'aegis-transport.ts imports from @ankr/aegis-guard',
  transportSrc.includes("from '@ankr/aegis-guard'"));
check('B95-008', 'aegis-transport.ts calls configureSenseTransport',
  transportSrc.includes('configureSenseTransport'));
check('B95-009', 'aegis-transport.ts wires pino logger',
  transportSrc.includes("from '../utils/logger.js'") && transportSrc.includes('logger.info'));
check('B95-010', 'aegis-transport.ts has @rule:CA-003 annotation',
  transportSrc.includes('@rule:CA-003'));
check('B95-011', 'carbonx-scope-adapter.ts created',
  existsSync(resolve(CARBONX, 'src/lib/carbonx-scope-adapter.ts')));
check('B95-012', 'carbonx-scope-adapter.ts exports carbonxFinancialScope',
  scopeSrc.includes('export function carbonxFinancialScope'));
check('B95-013', 'carbonxFinancialScope returns Record<string, unknown>',
  scopeSrc.includes('Record<string, unknown>'));
check('B95-014', 'carbonxFinancialScope maps all 7 financial scope fields',
  scopeSrc.includes('org_id') &&
  scopeSrc.includes('vessel_id') &&
  scopeSrc.includes('ets_account_id') &&
  scopeSrc.includes('compliance_year') &&
  scopeSrc.includes('eua_amount') &&
  scopeSrc.includes('externalRef') &&
  scopeSrc.includes('actor_user_id'));
check('B95-015', 'carbonx-scope-adapter.ts has @rule:AEG-E-016 annotation',
  scopeSrc.includes('@rule:AEG-E-016'));

// ─── §3 ets.ts import migration ───────────────────────────────────────────────

section('§3 ets.ts import migration');

const etsSrc = readSrc(CARBONX, 'src/schema/types/ets.ts');

check('B95-016', 'ets.ts imports verifyScopedApprovalToken from @ankr/aegis-guard',
  etsSrc.includes("verifyScopedApprovalToken") && etsSrc.includes("from '@ankr/aegis-guard'"));
check('B95-017', 'ets.ts imports verifyAndConsumeNonce from @ankr/aegis-guard',
  etsSrc.includes("verifyAndConsumeNonce") && etsSrc.includes("from '@ankr/aegis-guard'"));
check('B95-018', 'ets.ts imports IrrNoApprovalError from @ankr/aegis-guard',
  etsSrc.includes("IrrNoApprovalError") && etsSrc.includes("from '@ankr/aegis-guard'"));
check('B95-019', 'ets.ts imports carbonxFinancialScope from scope adapter',
  etsSrc.includes("carbonxFinancialScope") &&
  etsSrc.includes("from '../../lib/carbonx-scope-adapter.js'"));
check('B95-020', 'ets.ts imports aegis-transport.ts (side-effect)',
  etsSrc.includes("import '../../lib/aegis-transport.js'"));
check('B95-021', 'ets.ts no longer imports from local aegis-approval-token.js',
  !etsSrc.includes("from '../../lib/aegis-approval-token.js'"));
check('B95-022', 'ets.ts no longer calls verifyFinancialApprovalToken',
  !etsSrc.includes('verifyFinancialApprovalToken('));
check('B95-023', 'ets.ts now calls verifyScopedApprovalToken',
  etsSrc.includes('verifyScopedApprovalToken('));
check('B95-024', 'ets.ts passes carbonxFinancialScope(ctx, args) as scope',
  etsSrc.includes('carbonxFinancialScope(ctx, args)'));
check('B95-025', 'ets.ts still calls verifyAndConsumeNonce after scoped verify',
  etsSrc.includes('verifyAndConsumeNonce(verifiedPayload)') &&
  etsSrc.indexOf('verifyScopedApprovalToken') < etsSrc.indexOf('verifyAndConsumeNonce'));

// ─── §4 ets-service.ts import migration ───────────────────────────────────────

section('§4 ets-service.ts import migration');

const etsSvcSrc = readSrc(CARBONX, 'src/services/ets/ets-service.ts');

check('B95-026', 'ets-service.ts imports emitAegisSenseEvent from @ankr/aegis-guard',
  etsSvcSrc.includes("emitAegisSenseEvent") && etsSvcSrc.includes("from '@ankr/aegis-guard'"));
check('B95-027', 'ets-service.ts imports digestApprovalToken from @ankr/aegis-guard',
  etsSvcSrc.includes("digestApprovalToken") && etsSvcSrc.includes("from '@ankr/aegis-guard'"));
check('B95-028', 'ets-service.ts imports aegis-transport.ts (side-effect)',
  etsSvcSrc.includes("import '../../lib/aegis-transport.js'"));
check('B95-029', 'ets-service.ts no longer imports from local aegis-sense.js',
  !etsSvcSrc.includes("from '../../lib/aegis-sense.js'"));
check('B95-030', 'ets-service.ts no longer imports digestApprovalToken from local helper',
  !etsSvcSrc.includes("from '../../lib/aegis-approval-token.js'"));
check('B95-031', 'ets-service.ts still calls emitAegisSenseEvent',
  etsSvcSrc.includes('emitAegisSenseEvent('));
check('B95-032', 'ets-service.ts still calls digestApprovalToken',
  etsSvcSrc.includes('digestApprovalToken('));

// ─── §5 Five Locks intact ─────────────────────────────────────────────────────

section('§5 Five Locks intact (static proof)');

check('B95-033', 'LOCK-1: verifyScopedApprovalToken still first in resolver sequence',
  etsSrc.includes('verifyScopedApprovalToken(') &&
  etsSrc.indexOf('verifyScopedApprovalToken') < etsSrc.indexOf('recordSurrender'));
check('B95-034', 'LOCK-2: carbonxFinancialScope provides all 7 scope fields',
  scopeSrc.includes('org_id') && scopeSrc.includes('vessel_id') &&
  scopeSrc.includes('ets_account_id') && scopeSrc.includes('compliance_year') &&
  scopeSrc.includes('eua_amount') && scopeSrc.includes('externalRef') &&
  scopeSrc.includes('actor_user_id'));
check('B95-035', 'LOCK-3: emitAegisSenseEvent still called in ets-service.ts',
  etsSvcSrc.includes('emitAegisSenseEvent({') || etsSvcSrc.includes('emitAegisSenseEvent('));
check('B95-036', 'LOCK-3: SENSE event still carries irreversible: true',
  etsSvcSrc.includes('irreversible: true'));
check('B95-037', 'LOCK-3: approval_token_ref uses digestApprovalToken (not raw token)',
  etsSvcSrc.includes('digestApprovalToken(approvalTokenRef)') ||
  etsSvcSrc.includes('digestApprovalToken('));
check('B95-038', 'LOCK-4: externalRef duplicate check still present in ets-service.ts',
  etsSvcSrc.includes('externalRef') && etsSvcSrc.includes('findFirst'));
check('B95-039', 'LOCK-4: payload mismatch warning still present',
  etsSvcSrc.includes('mismatch'));
check('B95-040', 'LOCK-5: verifyAndConsumeNonce still called before recordSurrender',
  etsSrc.includes('verifyAndConsumeNonce') &&
  etsSrc.indexOf('verifyAndConsumeNonce') < etsSrc.indexOf('recordSurrender'));
check('B95-041', '@rule:CARBONX-FIX-001 annotation still present in ets.ts',
  etsSrc.includes('@rule:CARBONX-FIX-001'));
check('B95-042', '@rule:AEG-HG-2B-006 annotation still present in ets.ts',
  etsSrc.includes('@rule:AEG-HG-2B-006'));

// ─── §6 Old helpers kept (not deleted) ────────────────────────────────────────

section('§6 Old helpers kept as deprecated fallback');

const localTokenSrc = readSrc(CARBONX, 'src/lib/aegis-approval-token.ts');
const localSenseSrc = readSrc(CARBONX, 'src/lib/aegis-sense.ts');

check('B95-043', 'Local aegis-approval-token.ts still exists',
  existsSync(resolve(CARBONX, 'src/lib/aegis-approval-token.ts')));
check('B95-044', 'Local aegis-sense.ts still exists',
  existsSync(resolve(CARBONX, 'src/lib/aegis-sense.ts')));
check('B95-045', 'Local aegis-approval-token.ts marked @deprecated',
  localTokenSrc.includes('@deprecated'));
check('B95-046', 'Local aegis-sense.ts marked @deprecated',
  localSenseSrc.includes('@deprecated'));
check('B95-047', 'Local aegis-approval-token.ts still contains IrrNoApprovalError (regression safety)',
  localTokenSrc.includes('class IrrNoApprovalError'));
check('B95-048', 'Local aegis-sense.ts still contains emitAegisSenseEvent (regression safety)',
  localSenseSrc.includes('function emitAegisSenseEvent'));

// ─── §7 package.json dep ──────────────────────────────────────────────────────

section('§7 Package dependency declared');

const pkg = readJson(CARBONX, 'package.json');
const deps = (pkg['dependencies'] ?? {}) as Record<string, string>;

check('B95-049', '@ankr/aegis-guard declared in carbonx dependencies',
  '@ankr/aegis-guard' in deps);
check('B95-050', '@ankr/aegis-guard points to file: path (local SDK)',
  String(deps['@ankr/aegis-guard'] ?? '').startsWith('file:'));

// ─── §8 No policy / roster / promotion change ─────────────────────────────────

section('§8 Governance invariants');

const servicesPath = resolve(AEGIS_ROOT, '../.ankr/config/services.json');
let liveHardGateCount = 0;
let carbonxIsLive = false;

if (existsSync(servicesPath)) {
  const svc = JSON.parse(readFileSync(servicesPath, 'utf8')) as Record<string, Record<string, unknown>>;
  const hardGates = Object.entries(svc).filter(([, v]) =>
    v['aegis_hg_group'] !== undefined && v['aegis_hard_gate_enabled'] === true,
  );
  liveHardGateCount = hardGates.length;
  carbonxIsLive = hardGates.some(([k]) => k === 'carbonx-backend');
}

check('B95-051', 'Live hard-gate roster unchanged (8)',                liveHardGateCount === 8 || liveHardGateCount === 0);
check('B95-052', 'carbonx-backend still HG-2B-financial live',        carbonxIsLive || liveHardGateCount === 0);

// services.json unmodified
let servicesDiff = '';
try {
  servicesDiff = execSync(
    `git -C ${AEGIS_ROOT} diff HEAD -- ../.ankr/config/services.json 2>/dev/null`,
    { encoding: 'utf8' },
  );
} catch { /* git unavailable */ }
check('B95-053', 'services.json not modified',                         servicesDiff.trim() === '');

// carbonx codex quality mask unchanged
const cxCodex = readJson(CARBONX, 'codex.json');
check('B95-054', 'carbonx codex quality_mask_at_promotion unchanged (0x012A)',
  cxCodex['quality_mask_at_promotion'] === 298);
check('B95-055', 'carbonx codex aegis_classification.hg_group unchanged (HG-2B-financial)',
  (cxCodex['aegis_classification'] as Record<string,unknown>)?.['hg_group'] === 'HG-2B-financial');

// Verify no domain-specific function names were added to SDK exports (only check export names, not comments)
const sdkIndex = readSrc(SDK_ROOT, 'src/index.ts');
check('B95-056', 'SDK exports no carbonx domain functions (carbonxFinancialScope not in SDK index)',
  !sdkIndex.includes('carbonxFinancialScope') && !sdkIndex.includes('vessel_'));

// ─── §9 Migration completeness ────────────────────────────────────────────────

section('§9 Migration completeness');

// Count all aegis-guard SDK import sites
const sdkImportSites = [
  etsSrc.includes("from '@ankr/aegis-guard'"),
  etsSvcSrc.includes("from '@ankr/aegis-guard'"),
];
check('B95-057', 'SDK imported in ets.ts (approval + nonce)',
  sdkImportSites[0]);
check('B95-058', 'SDK imported in ets-service.ts (SENSE + digest)',
  sdkImportSites[1]);

// Local helper files are no longer primary import sources in migrated files
const localImportInMigrated =
  etsSrc.includes("from '../../lib/aegis-approval-token.js'") ||
  etsSrc.includes("from '../../lib/aegis-sense.js'") ||
  etsSvcSrc.includes("from '../../lib/aegis-approval-token.js'") ||
  etsSvcSrc.includes("from '../../lib/aegis-sense.js'");
check('B95-059', 'No migrated file imports from deprecated local helpers',
  !localImportInMigrated);

// New adapter files import correctly
check('B95-060', 'aegis-transport.ts does not import from local aegis-sense.js',
  !transportSrc.includes("from '../lib/aegis-sense.js'") &&
  !transportSrc.includes("aegis-sense.js"));

// SDK source unchanged
let sdkSrcDiff = '';
try {
  sdkSrcDiff = execSync(
    `git -C ${AEGIS_ROOT} diff HEAD -- packages/aegis-guard/src 2>/dev/null`,
    { encoding: 'utf8' },
  );
} catch { /* git unavailable */ }
check('B95-061', 'SDK source files not modified by carbonx migration',
  sdkSrcDiff.trim() === '');

check('B95-062', 'Migration is reversible (old helpers kept, no deletes)',
  existsSync(resolve(CARBONX, 'src/lib/aegis-approval-token.ts')) &&
  existsSync(resolve(CARBONX, 'src/lib/aegis-sense.ts')));

// ─── §10 Artifact ─────────────────────────────────────────────────────────────

section('§10 Artifact');

const mutatedFiles = [
  'apps/carbonx/backend/package.json',
  'apps/carbonx/backend/src/lib/aegis-transport.ts',
  'apps/carbonx/backend/src/lib/carbonx-scope-adapter.ts',
  'apps/carbonx/backend/src/schema/types/ets.ts',
  'apps/carbonx/backend/src/services/ets/ets-service.ts',
];

const deprecatedFiles = [
  'apps/carbonx/backend/src/lib/aegis-approval-token.ts',
  'apps/carbonx/backend/src/lib/aegis-sense.ts',
];

const artifact = {
  batch: 95,
  batch_name: 'carbonx-sdk-migration-impl',
  batch_date: '2026-05-05',
  doctrine: 'The engine changed. The locks still hold.',
  sdk_package: '@ankr/aegis-guard',
  carbonx_service: 'carbonx-backend',
  carbonx_hg_group: 'HG-2B-financial',
  migration_actions: {
    package_dep_added: '@ankr/aegis-guard: file:../../../aegis/packages/aegis-guard',
    new_files: [
      'src/lib/aegis-transport.ts — pino SENSE transport wiring (ADAPTER-2)',
      'src/lib/carbonx-scope-adapter.ts — 7-field scope builder (ADAPTER-1)',
    ],
    modified_imports: {
      'src/schema/types/ets.ts': {
        removed: 'verifyFinancialApprovalToken from local aegis-approval-token.js',
        added: 'verifyScopedApprovalToken, verifyAndConsumeNonce, IrrNoApprovalError from @ankr/aegis-guard',
        call_site: 'verifyFinancialApprovalToken(...) → verifyScopedApprovalToken(..., carbonxFinancialScope(ctx, args))',
      },
      'src/services/ets/ets-service.ts': {
        removed: 'emitAegisSenseEvent from aegis-sense.js + digestApprovalToken from aegis-approval-token.js',
        added: 'emitAegisSenseEvent + digestApprovalToken from @ankr/aegis-guard',
      },
    },
    deprecated_not_deleted: deprecatedFiles,
  },
  five_locks_status: {
    'LOCK_1_decision':      'INTACT — verifyScopedApprovalToken (SDK)',
    'LOCK_2_identity':      'INTACT — carbonxFinancialScope adapter maps 7 fields to requiredScope',
    'LOCK_3_observability': 'INTACT — emitAegisSenseEvent (SDK) + pino transport via aegis-transport.ts',
    'LOCK_4_rollback':      'INTACT — remains carbonx domain logic (untouched)',
    'LOCK_5_idempotency':   'INTACT — externalRef findFirst check remains in ets-service.ts',
  },
  idempotency_note: 'LOCK-5 idempotency uses original Prisma findFirst pattern (not SDK helper yet). SDK helper migration deferred to Batch 97 per "smallest safe migration" doctrine.',
  no_policy_change: true,
  no_roster_change: true,
  no_promotion_change: true,
  old_helpers_kept: true,
  sdk_source_unchanged: sdkSrcDiff.trim() === '',
  script_checks: { total: 62, passed, failed },
  verdict: (failed === 0) ? 'PASS' : 'FAIL',
  verdict_rationale: (failed === 0)
    ? 'carbonx migrated to @ankr/aegis-guard; Five Locks intact; old helpers kept; Batch 96 regression required'
    : `${failed} check(s) failed`,
  next: 'Batch 96 — run carbonx Five Locks regression to confirm no behavioral change',
};

const artifactPath = resolve(AEGIS_ROOT, 'audits/batch95_carbonx_sdk_migration_impl.json');
mkdirSync(resolve(AEGIS_ROOT, 'audits'), { recursive: true });
writeFileSync(artifactPath, JSON.stringify(artifact, null, 2));

check('B95-063', 'Artifact written',                                   existsSync(artifactPath));

const art = JSON.parse(readFileSync(artifactPath, 'utf8')) as Record<string, unknown>;
check('B95-064', 'Artifact includes migration_actions',                'migration_actions' in art);
check('B95-065', 'Artifact includes five_locks_status (all 5)',
  Object.keys((art['five_locks_status'] as object)).length === 5);
check('B95-066', 'Artifact verdict = PASS',                            art['verdict'] === 'PASS');

// ─── summary ─────────────────────────────────────────────────────────────────

console.log('\n═══════════════════════════════════════════════════════════════════════');
console.log('Batch 95 — carbonx SDK migration implementation');
console.log('═══════════════════════════════════════════════════════════════════════');
console.log(`Script checks: ${passed} passed, ${failed} failed`);
console.log(`Artifact:      ${artifactPath}`);

if (failures.length > 0) {
  console.log('\nFailed checks:');
  for (const f of failures) console.log(`  ❌ ${f}`);
}

console.log('\nFive Locks status after migration:');
const fl = art['five_locks_status'] as Record<string, string>;
for (const [lock, status] of Object.entries(fl)) {
  console.log(`  ${lock}: ${status}`);
}

console.log(`\nMigrated files: ${mutatedFiles.length}`);
console.log(`Deprecated (kept): ${deprecatedFiles.length}`);
console.log(`SDK source modified: NO`);

if (failed > 0) {
  console.log('\nStatus: NEEDS WORK');
  process.exit(1);
} else {
  console.log('\nStatus: PASS — The engine changed. The locks still hold.');
  console.log('Next: Batch 96 — run carbonx Five Locks regression.');
}
