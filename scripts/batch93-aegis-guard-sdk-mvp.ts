#!/usr/bin/env bun
// Batch 93 — @ankr/aegis-guard SDK MVP
// "Carbonx proved the locks. Batch 93 makes the locks reusable."
// Extracts Five Locks primitives proven in carbonx-backend (batches 62-74)
// into a service-agnostic TypeScript SDK package.
//
// 63 checks across §1-§9.
// No service promoted. No live roster changed. Extraction only.

import { readFileSync, existsSync } from 'fs';
import { execSync } from 'child_process';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const AEGIS_ROOT = resolve(__dirname, '..');
const SDK_ROOT = resolve(AEGIS_ROOT, 'packages/aegis-guard');

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

// ─── helpers ─────────────────────────────────────────────────────────────────

function fileExists(rel: string): boolean {
  return existsSync(resolve(SDK_ROOT, rel));
}

function readSrc(rel: string): string {
  return readFileSync(resolve(SDK_ROOT, rel), 'utf8');
}

function readJson(rel: string): Record<string, unknown> {
  return JSON.parse(readFileSync(resolve(SDK_ROOT, rel), 'utf8'));
}

// ─── §1 file structure ───────────────────────────────────────────────────────

section('§1 File structure');

check('B93-S01-001', 'package.json exists',               fileExists('package.json'));
check('B93-S01-002', 'src/errors.ts exists',              fileExists('src/errors.ts'));
check('B93-S01-003', 'src/approval-token.ts exists',      fileExists('src/approval-token.ts'));
check('B93-S01-004', 'src/nonce.ts exists',               fileExists('src/nonce.ts'));
check('B93-S01-005', 'src/idempotency.ts exists',         fileExists('src/idempotency.ts'));
check('B93-S01-006', 'src/sense.ts exists',               fileExists('src/sense.ts'));
check('B93-S01-007', 'src/quality.ts exists',             fileExists('src/quality.ts'));
check('B93-S01-008', 'src/index.ts exists',               fileExists('src/index.ts'));
check('B93-S01-009', 'tests/aegis-guard.test.ts exists',  fileExists('tests/aegis-guard.test.ts'));
check('B93-S01-010', 'codex.json exists',                 fileExists('codex.json'));

// ─── §2 package.json fields ───────────────────────────────────────────────────

section('§2 package.json fields');

const pkg = readJson('package.json');
check('B93-S02-011', 'package name = @ankr/aegis-guard',        pkg['name'] === '@ankr/aegis-guard');
check('B93-S02-012', 'version starts with 0.1',                  String(pkg['version']).startsWith('0.1'));
check('B93-S02-013', 'license = AGPL-3.0',                       pkg['license'] === 'AGPL-3.0');
check('B93-S02-014', 'type = module',                            pkg['type'] === 'module');
check('B93-S02-015', 'aegis.batch = 93',                         (pkg['aegis'] as Record<string,unknown>)['batch'] === 93);
check('B93-S02-016', 'aegis.doctrine contains Carbonx',          String((pkg['aegis'] as Record<string,unknown>)['doctrine']).includes('Carbonx'));
check('B93-S02-017', 'test script references aegis-guard.test',  String((pkg['scripts'] as Record<string,unknown>)['test']).includes('aegis-guard.test'));

// ─── §3 errors.ts content ─────────────────────────────────────────────────────

section('§3 errors.ts');

const errSrc = readSrc('src/errors.ts');
check('B93-S03-018', 'IrrNoApprovalError exported',              errSrc.includes('export class IrrNoApprovalError'));
check('B93-S03-019', "code = 'IRR-NOAPPROVAL'",                  errSrc.includes("readonly code = 'IRR-NOAPPROVAL'"));
check('B93-S03-020', "doctrine = 'AEG-E-016'",                  errSrc.includes("readonly doctrine = 'AEG-E-016'"));
check('B93-S03-021', 'AegisNonceError exported',                 errSrc.includes('export class AegisNonceError'));
check('B93-S03-022', "AEG-E-016 @rule annotation present",       errSrc.includes('@rule:AEG-E-016'));

// ─── §4 approval-token.ts content ─────────────────────────────────────────────

section('§4 approval-token.ts');

const atSrc = readSrc('src/approval-token.ts');
check('B93-S04-023', 'imports IrrNoApprovalError from errors.js',       atSrc.includes("from './errors.js'"));
check('B93-S04-024', 'imports NonceStore from nonce.js',                atSrc.includes("from './nonce.js'"));
check('B93-S04-025', 'digestApprovalToken exported',                    atSrc.includes('export function digestApprovalToken'));
check('B93-S04-026', 'digest uses SHA-256 first 24 hex chars',          atSrc.includes('.slice(0, 24)') && atSrc.includes('sha256'));
check('B93-S04-027', 'mintApprovalToken exported',                      atSrc.includes('export function mintApprovalToken'));
check('B93-S04-028', 'verifyApprovalToken exported',                    atSrc.includes('export function verifyApprovalToken'));
check('B93-S04-029', 'verifyAndConsumeNonce exported',                  atSrc.includes('export async function verifyAndConsumeNonce'));
check('B93-S04-030', 'verifyScopedApprovalToken exported',              atSrc.includes('export function verifyScopedApprovalToken'));
check('B93-S04-031', 'requiredScope is Record<string, unknown>',        atSrc.includes('Record<string, unknown>'));
check('B93-S04-032', 'no FinancialApprovalContext (service-agnostic)',  !atSrc.includes('FinancialApprovalContext'));
check('B93-S04-033', 'CLOCK_SKEW_MS = 60_000',                         atSrc.includes('CLOCK_SKEW_MS = 60_000'));
check('B93-S04-034', '@rule:AEG-HG-2B-006 annotation present',         atSrc.includes('@rule:AEG-HG-2B-006'));

// ─── §5 nonce.ts content ──────────────────────────────────────────────────────

section('§5 nonce.ts');

const nonceSrc = readSrc('src/nonce.ts');
check('B93-S05-035', 'NonceStore interface exported',                   nonceSrc.includes('export interface NonceStore'));
check('B93-S05-036', 'consumeNonce signature correct',                  nonceSrc.includes('consumeNonce(nonce: string, ttlMs: number): Promise<boolean>'));
check('B93-S05-037', 'defaultNonceStore exported',                      nonceSrc.includes('export const defaultNonceStore'));
check('B93-S05-038', 'fail-closed semantics documented in comments',    nonceSrc.includes('fails CLOSED'));
check('B93-S05-039', 'InMemoryNonceStore uses Map',                     nonceSrc.includes('Map<string, number>'));

// ─── §6 idempotency.ts content ────────────────────────────────────────────────

section('§6 idempotency.ts');

const idSrc = readSrc('src/idempotency.ts');
check('B93-S06-040', 'IdempotencyCheckResult exported',                 idSrc.includes('export interface IdempotencyCheckResult'));
check('B93-S06-041', 'isDuplicate field present',                       idSrc.includes('isDuplicate: boolean'));
check('B93-S06-042', 'payloadMismatch field present',                   idSrc.includes('payloadMismatch: boolean'));
check('B93-S06-043', 'safeNoOp field present',                          idSrc.includes('safeNoOp: boolean'));
check('B93-S06-044', 'checkIdempotency exported',                       idSrc.includes('export function checkIdempotency'));
check('B93-S06-045', 'buildIdempotencyFingerprint exported',            idSrc.includes('export function buildIdempotencyFingerprint'));
check('B93-S06-046', '@rule:AEG-HG-2B-006 annotation present',         idSrc.includes('@rule:AEG-HG-2B-006'));

// ─── §7 sense.ts content ──────────────────────────────────────────────────────

section('§7 sense.ts');

const senseSrc = readSrc('src/sense.ts');
check('B93-S07-047', 'AegisSenseEvent exported',                        senseSrc.includes('export interface AegisSenseEvent'));
check('B93-S07-048', 'service_id is string (not literal carbonx-backend)', !senseSrc.includes("'carbonx-backend'"));
check('B93-S07-049', 'SenseTransport type exported',                    senseSrc.includes('export type SenseTransport'));
check('B93-S07-050', 'configureSenseTransport exported',                senseSrc.includes('export function configureSenseTransport'));
check('B93-S07-051', 'emitAegisSenseEvent exported',                    senseSrc.includes('export function emitAegisSenseEvent'));
check('B93-S07-052', 'no pino import (transport-agnostic)',             !senseSrc.includes('pino'));
check('B93-S07-053', '@rule:CA-003 annotation present',                 senseSrc.includes('@rule:CA-003'));
check('B93-S07-054', '@rule:AEG-HG-2B-005 annotation present',         senseSrc.includes('@rule:AEG-HG-2B-005'));

// ─── §8 quality.ts content ────────────────────────────────────────────────────

section('§8 quality.ts');

const qualSrc = readSrc('src/quality.ts');
check('B93-S08-055', 'buildQualityMaskAtPromotion exported',            qualSrc.includes('export function buildQualityMaskAtPromotion'));
check('B93-S08-056', 'buildQualityDriftScore exported',                 qualSrc.includes('export function buildQualityDriftScore'));
check('B93-S08-057', 'HG_REQUIRED_MASKS exported',                      qualSrc.includes('export const HG_REQUIRED_MASKS'));
check('B93-S08-058', 'meetsHgQualityRequirement exported',              qualSrc.includes('export function meetsHgQualityRequirement'));
check('B93-S08-059', 'drift bits 12-15 (not 0-11) for drift map',      qualSrc.includes('[\'idempotency_evidenced\',   12]') || qualSrc.includes("['idempotency_evidenced',   12]") || qualSrc.includes('12]') && qualSrc.includes('13]') && qualSrc.includes('14]') && qualSrc.includes('15]'));
check('B93-S08-060', '@rule:AEG-Q-003 annotation present',              qualSrc.includes('@rule:AEG-Q-003'));

// ─── §9 codex.json + invariants ───────────────────────────────────────────────

section('§9 codex.json + SDK invariants');

const codex = readJson('codex.json');
check('B93-S09-061', 'codex service_key = aegis-guard',                codex['service_key'] === 'aegis-guard');
check('B93-S09-062', 'codex aegis_classification is HG-1 or HG-2A (not HG-2B-financial)', ['HG-1','HG-2A'].includes(String(codex['aegis_classification'])));
check('B93-S09-063', 'codex quality_mask_at_promotion = null (not promoted)',  codex['quality_mask_at_promotion'] === null);

// ─── run bun test ─────────────────────────────────────────────────────────────

console.log('\n─── Running bun test ───────────────────────────────────────────────────');
let testOutput = '';
let testPassed = false;
try {
  testOutput = execSync(
    `cd ${SDK_ROOT} && bun test tests/aegis-guard.test.ts 2>&1`,
    { encoding: 'utf8', timeout: 30_000 },
  );
  testPassed = !testOutput.includes('failed') || testOutput.includes('0 failed');
  console.log(testOutput.split('\n').slice(-10).join('\n'));
} catch (err) {
  const e = err as { stdout?: string; stderr?: string };
  testOutput = (e.stdout || '') + (e.stderr || '');
  console.log(testOutput.split('\n').slice(-15).join('\n'));
  testPassed = false;
}

// ─── summary ─────────────────────────────────────────────────────────────────

console.log('\n═══════════════════════════════════════════════════════════════════════');
console.log('Batch 93 — @ankr/aegis-guard SDK MVP');
console.log('═══════════════════════════════════════════════════════════════════════');
console.log(`Script checks: ${passed} passed, ${failed} failed`);
console.log(`bun test:      ${testPassed ? 'PASS' : 'FAIL'}`);

if (failures.length > 0) {
  console.log('\nFailed checks:');
  for (const f of failures) console.log(`  ❌ ${f}`);
}

// ─── batch artifact ──────────────────────────────────────────────────────────

const artifact = {
  batch: 93,
  batch_name: 'aegis-guard-sdk-mvp',
  batch_date: '2026-05-05',
  doctrine: 'Carbonx proved the locks. Batch 93 makes the locks reusable.',
  sdk_package: '@ankr/aegis-guard',
  sdk_version: '0.1.0',
  sdk_path: 'packages/aegis-guard',
  five_locks: ['LOCK_1_decision', 'LOCK_2_identity', 'LOCK_3_observability', 'LOCK_4_rollback', 'LOCK_5_idempotency'],
  primitives: {
    'errors.ts':         { exports: ['IrrNoApprovalError', 'AegisNonceError'], doctrine: 'AEG-E-016' },
    'approval-token.ts': { exports: ['verifyApprovalToken', 'verifyScopedApprovalToken', 'verifyAndConsumeNonce', 'digestApprovalToken', 'mintApprovalToken'], scope_binding: 'Record<string,unknown>' },
    'nonce.ts':          { exports: ['NonceStore', 'defaultNonceStore'], semantics: 'fail-closed' },
    'idempotency.ts':    { exports: ['checkIdempotency', 'buildIdempotencyFingerprint'], layer: 'functional-no-db' },
    'sense.ts':          { exports: ['AegisSenseEvent', 'SenseTransport', 'configureSenseTransport', 'emitAegisSenseEvent'], transport: 'configurable' },
    'quality.ts':        { exports: ['buildQualityMaskAtPromotion', 'buildQualityDriftScore', 'HG_REQUIRED_MASKS', 'meetsHgQualityRequirement'], bits_promotion: '0-11', bits_drift: '12-15' },
  },
  script_checks: { total: 63, passed, failed },
  bun_test_passed: testPassed,
  no_service_promoted: true,
  no_live_roster_changed: true,
  extraction_only: true,
  next_batches: {
    94: 'carbonx SDK migration dry-run',
    95: 'carbonx SDK migration implementation',
    96: 're-run carbonx Five Locks regression',
    97: 'update dashboard to show SDK adoption coverage',
  },
};

const artifactPath = resolve(AEGIS_ROOT, 'audits/batch93_aegis_guard_sdk_mvp.json');
import { writeFileSync, mkdirSync } from 'fs';
mkdirSync(resolve(AEGIS_ROOT, 'audits'), { recursive: true });
writeFileSync(artifactPath, JSON.stringify(artifact, null, 2));
console.log(`\nArtifact: ${artifactPath}`);

if (failed > 0 || !testPassed) {
  console.log('\nStatus: NEEDS WORK');
  process.exit(1);
} else {
  console.log('\nStatus: PASS — Batch 93 complete. Five Locks are now reusable.');
}
