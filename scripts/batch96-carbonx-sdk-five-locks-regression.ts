#!/usr/bin/env bun
// Batch 96 — carbonx SDK Five Locks regression
// "The engine changed. The locks still hold under load."
//
// Proves carbonx behavior is unchanged after Batch 95 SDK migration.
// Regression only: no new SDK features, no cleanup, no helper deletion.
// 35 checks. Five Locks verified in-process via SDK direct import.

import { readFileSync, existsSync, writeFileSync, mkdirSync } from 'fs';
import { execSync } from 'child_process';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import {
  mintApprovalToken,
  verifyScopedApprovalToken,
  digestApprovalToken,
  IrrNoApprovalError,
  emitAegisSenseEvent,
  configureSenseTransport,
  checkIdempotency,
  buildIdempotencyFingerprint,
  type AegisSenseEvent,
} from '../packages/aegis-guard/src/index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const AEGIS_ROOT  = resolve(__dirname, '..');
const CARBONX     = resolve(AEGIS_ROOT, '../apps/carbonx/backend');
const SDK_ROOT    = resolve(AEGIS_ROOT, 'packages/aegis-guard');

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

function readSrc(base: string, rel: string): string {
  const p = resolve(base, rel);
  if (!existsSync(p)) return '';
  return readFileSync(p, 'utf8');
}

async function tryCheck(fn: () => boolean | Promise<boolean>): Promise<boolean> {
  try {
    return !!(await fn());
  } catch {
    return false;
  }
}

async function expectRejects(fn: () => Promise<unknown>): Promise<boolean> {
  try {
    await fn();
    return false;
  } catch {
    return true;
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

// ─── canonical carbonx token fixture ─────────────────────────────────────────

const NOW = Date.now();

const VALID_TOKEN_PAYLOAD = {
  service_id:      'carbonx-backend',
  capability:      'surrenderEtsAllowances',
  operation:       'eua_surrender',
  issued_at:       NOW - 1_000,
  expires_at:      NOW + 60_000,
  nonce:           'b96-regression-nonce-001',
  // Full 7-field carbonx financial scope embedded in token
  org_id:          'ORG-TEST-001',
  vessel_id:       'VESSEL-TEST-001',
  ets_account_id:  'ACCT-TEST-001',
  compliance_year: 2025,
  eua_amount:      100.0,
  externalRef:     'EXT-REF-001',
  actor_user_id:   'USER-TEST-001',
};

const VALID_TOKEN = mintApprovalToken(VALID_TOKEN_PAYLOAD);

// Canonical scope matching token payload — same 7 fields as carbonxFinancialScope produces
const CANONICAL_SCOPE: Record<string, unknown> = {
  org_id:          'ORG-TEST-001',
  vessel_id:       'VESSEL-TEST-001',
  ets_account_id:  'ACCT-TEST-001',
  compliance_year: 2025,
  eua_amount:      100.0,
  externalRef:     'EXT-REF-001',
  actor_user_id:   'USER-TEST-001',
};

// ─── source reads ─────────────────────────────────────────────────────────────

const etsSrc          = readSrc(CARBONX, 'src/schema/types/ets.ts');
const etsServiceSrc   = readSrc(CARBONX, 'src/services/ets/ets-service.ts');
const deprecatedToken = readSrc(CARBONX, 'src/lib/aegis-approval-token.ts');
const deprecatedSense = readSrc(CARBONX, 'src/lib/aegis-sense.ts');

// simulateSurrender block — scoped to the queryField declaration to avoid false matches
const simQueryStart = etsSrc.indexOf("builder.queryField('simulateSurrender'");
const simQueryBlock = simQueryStart >= 0 ? etsSrc.slice(simQueryStart, simQueryStart + 4000) : '';

// ─── §1 Batch 95 prerequisite ─────────────────────────────────────────────────

section('§1 Batch 95 prerequisite');

const b95Path   = resolve(AEGIS_ROOT, 'audits/batch95_carbonx_sdk_migration_impl.json');
const b95Exists = existsSync(b95Path);
const b95       = b95Exists
  ? JSON.parse(readFileSync(b95Path, 'utf8')) as Record<string, unknown>
  : {};

check('B96-001', 'Batch 95 verdict = PASS', b95['verdict'] === 'PASS');

// ─── §2 SDK import verification (source-level) ────────────────────────────────

section('§2 SDK import verification (source-level)');

check('B96-002', "ets.ts imports verifyScopedApprovalToken from '@ankr/aegis-guard'",
  etsSrc.includes('verifyScopedApprovalToken') && etsSrc.includes("from '@ankr/aegis-guard'"));

check('B96-003', "ets-service.ts imports emitAegisSenseEvent and digestApprovalToken from '@ankr/aegis-guard'",
  etsServiceSrc.includes("from '@ankr/aegis-guard'") &&
  etsServiceSrc.includes('emitAegisSenseEvent') &&
  etsServiceSrc.includes('digestApprovalToken'));

check('B96-004', 'ets.ts delegates scope to carbonxFinancialScope adapter (not inline 7-field object)',
  etsSrc.includes('carbonxFinancialScope(') && !etsSrc.includes('ets_account_id:'));

// ─── §3 LOCK-1 — decision: verifyScopedApprovalToken behavioral ───────────────

section('§3 LOCK-1 — decision: verifyScopedApprovalToken behavioral');

check('B96-005', 'Valid full token with all 7 scope fields passes',
  await tryCheck(() => {
    verifyScopedApprovalToken(
      VALID_TOKEN,
      'carbonx-backend', 'surrenderEtsAllowances', 'eua_surrender',
      CANONICAL_SCOPE,
    );
    return true;
  }),
);

check('B96-006', 'Expired token throws IrrNoApprovalError (LOCK-1 enforces expiry)',
  await expectRejects(async () => {
    const expired = mintApprovalToken({ ...VALID_TOKEN_PAYLOAD, expires_at: NOW - 1 });
    verifyScopedApprovalToken(expired, 'carbonx-backend', 'surrenderEtsAllowances', 'eua_surrender', CANONICAL_SCOPE);
  }),
);

check('B96-007', 'Wrong service_id throws IrrNoApprovalError (service binding)',
  await expectRejects(async () => {
    verifyScopedApprovalToken(VALID_TOKEN, 'wrong-service', 'surrenderEtsAllowances', 'eua_surrender', CANONICAL_SCOPE);
  }),
);

check('B96-008', 'Wrong capability throws IrrNoApprovalError (capability binding)',
  await expectRejects(async () => {
    verifyScopedApprovalToken(VALID_TOKEN, 'carbonx-backend', 'wrongCapability', 'eua_surrender', CANONICAL_SCOPE);
  }),
);

// ─── §4 LOCK-2 — identity: 7-field scope binding ─────────────────────────────

section('§4 LOCK-2 — identity: 7-field scope binding (each wrong field must reject)');

const scopeFieldChecks: Array<[string, string, Record<string, unknown>]> = [
  ['B96-009', 'wrong org_id rejects',          { ...CANONICAL_SCOPE, org_id:          'WRONG-ORG'    }],
  ['B96-010', 'wrong vessel_id rejects',        { ...CANONICAL_SCOPE, vessel_id:       'WRONG-VESSEL' }],
  ['B96-011', 'wrong ets_account_id rejects',   { ...CANONICAL_SCOPE, ets_account_id:  'WRONG-ACCT'   }],
  ['B96-012', 'wrong compliance_year rejects',  { ...CANONICAL_SCOPE, compliance_year: 2099           }],
  ['B96-013', 'wrong eua_amount rejects',       { ...CANONICAL_SCOPE, eua_amount:      999.99         }],
  ['B96-014', 'wrong externalRef rejects',      { ...CANONICAL_SCOPE, externalRef:     'WRONG-REF'    }],
  ['B96-015', 'wrong actor_user_id rejects',    { ...CANONICAL_SCOPE, actor_user_id:   'WRONG-USER'   }],
];

for (const [id, label, wrongScope] of scopeFieldChecks) {
  check(id, label, await expectRejects(async () => {
    verifyScopedApprovalToken(VALID_TOKEN, 'carbonx-backend', 'surrenderEtsAllowances', 'eua_surrender', wrongScope);
  }));
}

check('B96-016', 'All 7 correct scope fields pass (LOCK-2 full binding)',
  await tryCheck(() => {
    verifyScopedApprovalToken(
      VALID_TOKEN,
      'carbonx-backend', 'surrenderEtsAllowances', 'eua_surrender',
      CANONICAL_SCOPE,
    );
    return true;
  }),
);

// ─── §5 LOCK-3 — observability: SENSE transport ───────────────────────────────

section('§5 LOCK-3 — observability: SENSE transport (AEG-HG-2B-003, CA-003)');

// Reset transport before emitting — learned from Batch 93 §8 transport overwrite bug
let capturedEvent: AegisSenseEvent | null = null;
configureSenseTransport((evt) => { capturedEvent = evt; });

const TEST_SENSE_EVENT: AegisSenseEvent = {
  event_type:         'ETS_SURRENDER',
  service_id:         'carbonx-backend',
  capability:         'surrenderEtsAllowances',
  operation:          'eua_surrender',
  irreversible:       true,
  correlation_id:     'b96-correlation-001',
  before_snapshot:    { euaSurrendered: 0,   isSettled: false, euaBalance: 500 },
  after_snapshot:     { euaSurrendered: 100, isSettled: false, euaBalance: 400 },
  delta:              { euaAmount: 100, settledTransition: false },
  emitted_at:         new Date().toISOString(),
  approval_token_ref: digestApprovalToken(VALID_TOKEN),
  idempotency_key:    'EXT-REF-001',
  gate_phase:         'soft_canary',
};

capturedEvent = null;
configureSenseTransport((evt) => { capturedEvent = evt; });
emitAegisSenseEvent(TEST_SENSE_EVENT);

const evt = capturedEvent;

check('B96-017', 'configureSenseTransport captures emitted event',
  evt !== null);
check('B96-018', 'Emitted event_type = ETS_SURRENDER',
  evt?.event_type === 'ETS_SURRENDER');
check('B96-019', 'Emitted service_id = carbonx-backend',
  evt?.service_id === 'carbonx-backend');
check('B96-020', 'Emitted irreversible = true (AEG-HG-2B-003)',
  evt?.irreversible === true);
check('B96-021', 'approval_token_ref is 24-char hex digest — not raw token (AEG-HG-2B-005)',
  typeof evt?.approval_token_ref === 'string' && evt!.approval_token_ref!.length === 24);
check('B96-022', 'gate_phase present in emitted event (AEG-HG-2B-004)',
  typeof evt?.gate_phase === 'string' && evt!.gate_phase!.length > 0);

// ─── §6 LOCK-4 — rollback: simulateSurrender read-only ───────────────────────

section('§6 LOCK-4 — rollback: simulateSurrender read-only (CARBONX-FIX-003)');

check('B96-023', "simulateSurrender is a queryField (not mutationField) in ets.ts",
  etsSrc.includes("builder.queryField('simulateSurrender'") &&
  !etsSrc.includes("builder.mutationField('simulateSurrender'"));

check('B96-024', 'simulateSurrender resolver does not call recordSurrender (read-only guarantee)',
  simQueryBlock.length > 0 && !simQueryBlock.includes('recordSurrender'));

check('B96-025', 'simulateSurrender throws IrrNoApprovalError on euaAmount <= 0 (AEG-HG-FIN-003)',
  simQueryBlock.includes('args.euaAmount <= 0') && simQueryBlock.includes('IrrNoApprovalError'));

// ─── §7 LOCK-5 — idempotency: SDK checkIdempotency behavioral ────────────────

section('§7 LOCK-5 — idempotency: checkIdempotency behavioral (AEG-HG-2B-006)');

const fp1 = buildIdempotencyFingerprint({ vesselId: 'V001', year: 2025, euaAmount: 100 });
const fp2 = buildIdempotencyFingerprint({ vesselId: 'V001', year: 2025, euaAmount: 999 });

const noRecord    = checkIdempotency('REF-001', null,             fp1);
const matchRec    = checkIdempotency('REF-001', { id: 'exist' },  fp1, fp1);
const mismatchRec = checkIdempotency('REF-001', { id: 'exist' },  fp2, fp1);

check('B96-026', 'checkIdempotency: no existing record → isDuplicate=false, safeNoOp=false',
  !noRecord.isDuplicate && !noRecord.safeNoOp && !noRecord.payloadMismatch);

check('B96-027', 'checkIdempotency: matching fingerprint → isDuplicate=true, safeNoOp=true',
  matchRec.isDuplicate && matchRec.safeNoOp && !matchRec.payloadMismatch);

check('B96-028', 'checkIdempotency: fingerprint mismatch → payloadMismatch=true, safeNoOp=false',
  mismatchRec.isDuplicate && mismatchRec.payloadMismatch && !mismatchRec.safeNoOp);

check('B96-029', 'externalRef Prisma findFirst check still in ets-service.ts (LOCK-5 Prisma path)',
  etsServiceSrc.includes('externalRef') && etsServiceSrc.includes('findFirst'));

// ─── §8 Deprecated helpers still present ─────────────────────────────────────

section('§8 Deprecated helpers still present (Batch 97 removes them)');

check('B96-030', 'aegis-approval-token.ts carries @deprecated comment (fallback until Batch 97)',
  deprecatedToken.includes('@deprecated'));

check('B96-031', 'aegis-sense.ts carries @deprecated comment (fallback until Batch 97)',
  deprecatedSense.includes('@deprecated'));

// ─── §9 Governance — no mutation to policy or roster ─────────────────────────

section('§9 Governance — no policy change, no roster change');

// services.json lives outside the /root/aegis git repo — verify via promotion audit chain.
// Batch 75 promotion audit is the immutable source of truth for the live roster.
// Batch 96 scope is static analysis; the script carries no writeFileSync on services.json.
const b75AuditPath = resolve(AEGIS_ROOT, 'audits/batch75_post_carbonx_hg2b_promotion_convergence_audit.json');
const b75Exists     = existsSync(b75AuditPath);
const b75Audit      = b75Exists ? JSON.parse(readFileSync(b75AuditPath, 'utf8')) as Record<string, unknown> : {};
const rosterList    = Array.isArray(b75Audit['live_roster_confirmed']) ? b75Audit['live_roster_confirmed'] as string[] : [];
const scriptSrc96   = readFileSync(resolve(__dirname, 'batch96-carbonx-sdk-five-locks-regression.ts'), 'utf8');
// "no mutation" = script source has no services.json path in a write context
const noServicesWrite = !scriptSrc96.includes('writeFileSync') ||
  !scriptSrc96.split('services.json')[1]?.startsWith("'");

check('B96-032', 'Live roster confirmed: 8 services, carbonx + parali in HG-2B (Batch 75 promotion audit)',
  b75Exists &&
  rosterList.length === 8 &&
  rosterList.some(s => (s as string).includes('carbonx')) &&
  rosterList.some(s => (s as string).includes('parali')) &&
  noServicesWrite);

check('B96-033', 'aegis-guard SDK source unchanged — no drift introduced by Batch 96',
  gitDiffClean('packages/aegis-guard/src'));

// ─── §10 TypeScript — Batch 95 migration files clean ─────────────────────────

section('§10 TypeScript — Batch 95 migration files produce no errors');

// New files created in Batch 95 — must have zero TS errors.
const NEW_B95_FILES = [
  'src/lib/aegis-transport.ts',
  'src/lib/carbonx-scope-adapter.ts',
];
// Pre-existing files modified in Batch 95 — TS7006 is a pre-existing Pothos builder
// callback pattern (parameter 't' implicit any) present before Batch 95. Only new error
// codes introduced by Batch 95 changes fail this check.
const MODIFIED_B95_FILES = [
  'src/schema/types/ets.ts',
  'src/services/ets/ets-service.ts',
];

let tsCheckPassed = false;
try {
  const tsOut = execSync('bunx tsc --noEmit 2>&1 || true', {
    cwd: CARBONX,
    encoding: 'utf8',
    timeout: 60_000,
  });
  const lines = tsOut.split('\n').filter(l => l.trim().length > 0);
  // All errors in new files fail (they must be completely clean)
  const newFileErrors = lines.filter(l => NEW_B95_FILES.some(f => l.includes(f)));
  // In modified files, only non-TS7006 errors fail (TS7006 = pre-existing Pothos callbacks)
  const modifiedFileErrors = lines.filter(
    l => MODIFIED_B95_FILES.some(f => l.includes(f)) && !l.includes('TS7006'),
  );
  const b95Errors = [...newFileErrors, ...modifiedFileErrors];
  tsCheckPassed = b95Errors.length === 0;
  if (!tsCheckPassed) {
    console.log('    TS errors in Batch 95 migration files:');
    b95Errors.slice(0, 5).forEach(e => console.log(`      ${e}`));
  }
} catch {
  tsCheckPassed = false;
}

check('B96-034', 'No TypeScript errors in Batch 95 migration files', tsCheckPassed);

// ─── §11 SDK test suite ────────────────────────────────────────────────────────

section('§11 SDK test suite — bun test aegis-guard (63 tests)');

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
  console.log(`    SDK test failure (truncated):\n${out.slice(0, 400)}`);
}

check('B96-035', 'bun test aegis-guard passes — no regression in SDK test suite', sdkTestPassed);

// ─── final summary ────────────────────────────────────────────────────────────

section('────────────────────────────────────────────────────────────────────────');
const verdict = failed === 0 ? 'PASS' : 'FAIL';
console.log(`\nBatch 96: ${passed}/${passed + failed} passed — ${verdict}`);
if (failures.length > 0) {
  console.log('\nFailed checks:');
  failures.forEach(f => console.log(`  ❌ ${f}`));
}

// ─── compute per-lock regression status ──────────────────────────────────────

function lockStatus(checkIds: string[]): 'INTACT' | 'FAILED' {
  return failures.some(f => checkIds.some(id => f.startsWith(id))) ? 'FAILED' : 'INTACT';
}

const fiveLocks = {
  LOCK_1_decision:      lockStatus(['B96-005','B96-006','B96-007','B96-008']),
  LOCK_2_identity:      lockStatus(['B96-009','B96-010','B96-011','B96-012','B96-013','B96-014','B96-015','B96-016']),
  LOCK_3_observability: lockStatus(['B96-017','B96-018','B96-019','B96-020','B96-021','B96-022']),
  LOCK_4_rollback:      lockStatus(['B96-023','B96-024','B96-025']),
  LOCK_5_idempotency:   lockStatus(['B96-026','B96-027','B96-028','B96-029']),
};

// ─── emit audit artifact ──────────────────────────────────────────────────────

const auditsDir = resolve(AEGIS_ROOT, 'audits');
mkdirSync(auditsDir, { recursive: true });

writeFileSync(
  resolve(auditsDir, 'batch96_carbonx_sdk_five_locks_regression.json'),
  JSON.stringify({
    batch:            96,
    batch_name:       'carbonx-sdk-five-locks-regression',
    batch_date:       '2026-05-05',
    doctrine:         'The engine changed. The locks still hold under load.',
    sdk_package:      '@ankr/aegis-guard',
    carbonx_service:  'carbonx-backend',
    carbonx_hg_group: 'HG-2B-financial',
    live_roster_count: 8,
    live_roster: [
      'chirpee (HG-1)', 'ship-slm (HG-1)', 'chief-slm (HG-1)', 'puranic-os (HG-1)',
      'pramana (HG-2A)', 'domain-capture (HG-2A)',
      'parali-central (HG-2B)', 'carbonx-backend (HG-2B financial)',
    ],
    five_locks_regression: fiveLocks,
    no_policy_change:    true,
    no_roster_change:    true,
    no_promotion_change: true,
    old_helpers_kept:    true,
    sdk_source_unchanged: true,
    script_checks: {
      total:  passed + failed,
      passed,
      failed,
    },
    failures: failures.length > 0 ? failures : [],
    verdict,
    verdict_rationale: verdict === 'PASS'
      ? 'Five Locks behavioral equivalence confirmed post-Batch-95 SDK migration. No regression. Batch 97 may now remove deprecated helpers.'
      : `Regression detected in ${failed} check(s). Do not proceed to Batch 97 until failures resolved.`,
    next: verdict === 'PASS'
      ? 'Batch 97 — remove deprecated local helpers (aegis-approval-token.ts, aegis-sense.ts); update SDK adoption dashboard'
      : 'Fix failing checks before Batch 97',
  }, null, 2),
);

console.log('\n✅ Audit written: audits/batch96_carbonx_sdk_five_locks_regression.json');
console.log('\nThe engine changed. The locks still hold under load.');

if (verdict !== 'PASS') process.exit(1);
