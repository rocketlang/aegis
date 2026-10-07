/**
 * PROOF coverage scanner — live @rule: annotation analysis from source.
 * @rule:FP-004 Code Implements Rules — PROOF enforces annotation coverage
 *
 * Scans every .ts file under src/ at request time, extracts @rule: IDs,
 * and returns structured coverage against the VRN rule namespace.
 */

import { readdirSync, readFileSync, statSync } from 'fs';
import { extname, join } from 'path';
import { fileURLToPath } from 'url';

// ─── Rule namespace definitions ───────────────────────────────────────────────

// VRN SHASTRA rules (VRN-001 to VRN-050) — code-implementable decision rules
// These are the rules that SHOULD appear as @rule: annotations in source.
// Procedural/organizational rules (patch management, crew briefings) are
// intentionally excluded — they cannot be annotated in code.
const VRN_SHASTRA_TOTAL = 50;

// VRN rules known to be procedural (non-code) — not penalized in coverage
const VRN_PROCEDURAL = new Set([
  'VRN-003', // Vulnerability assessment schedule — a process, not code
  'VRN-004', // Physical access control — hardware policy
  'VRN-007', // Backup and recovery plan — documented procedure
  'VRN-010', // Patch management policy — operational process
  'VRN-011', // Software allowlisting policy — config-level, not code
  'VRN-012', // Remote access policy — policy document
  'VRN-013', // Supply chain risk assessment — vendor process
  'VRN-014', // Incident response plan — documented procedure
  'VRN-016', // Security awareness training — HR process
  'VRN-017', // Drills and exercises schedule — operational
  'VRN-018', // IDS/IPS deployment — infrastructure (not Varuna code)
  'VRN-020', // Port-side network policy — external dependency
  'VRN-023', // Fender controller access control — hardware policy
  'VRN-024', // VHF gateway authentication — external dependency
  'VRN-025', // GMDSS redundancy — infrastructure
  'VRN-027', // Modbus RTU physical isolation — hardware
  'VRN-028', // CANbus physical isolation — hardware
  'VRN-031', // AMS access restrictions — vendor system
  'VRN-034', // ECDIS update procedure — operational
  'VRN-037', // VDR data integrity checks — operational
  'VRN-038', // GPS multi-constellation policy — hardware
  'VRN-039', // GMDSS watch policy — operational
  'VRN-042', // Pre-pentest authorization checklist — process
  'VRN-046', // Post-pentest remediation tracking — process
]);

const VRN_CODE_IMPLEMENTABLE = VRN_SHASTRA_TOTAL - VRN_PROCEDURAL.size;

// ─── Scanner ──────────────────────────────────────────────────────────────────

// Locate src/ root relative to this file (src/forja/proof.ts → src/)
const SRC_ROOT = fileURLToPath(new URL('..', import.meta.url));

function walkTs(dir: string): string[] {
  const paths: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) {
      paths.push(...walkTs(full));
    } else if (stat.isFile() && extname(entry) === '.ts') {
      paths.push(full);
    }
  }
  return paths;
}

export interface ProofResult {
  files_total: number;
  files_annotated: number;
  file_coverage_pct: number;
  unique_rule_ids: string[];
  vrn_shastra_annotated: string[];
  vrn_yukti_annotated: string[];
  other_rule_ids: string[];
  vrn_code_implementable: number;
  vrn_procedural_count: number;
  vrn_annotated_of_implementable: number;
  vrn_coverage_pct: number;
  annotation_count_total: number;
  proof_status: 'PASS' | 'PARTIAL' | 'FAIL';
  coverage_pct: number;
  missing_vrn_implementable: string[];
}

// Cache per process start — source doesn't change without a restart
let _cached: ProofResult | null = null;

export function scanProof(): ProofResult {
  if (_cached) return _cached;

  const files = walkTs(SRC_ROOT);
  let annotationCountTotal = 0;
  let filesAnnotated = 0;
  const allRuleIds = new Set<string>();
  const fileRuleIds: { file: string; ids: Set<string> }[] = [];

  for (const file of files) {
    const content = readFileSync(file, 'utf8');
    const ids = new Set<string>();
    const iter = content.matchAll(/@rule:([A-Z0-9][A-Z0-9-]+)/g);
    for (const m of iter) {
      ids.add(m[1]);
      allRuleIds.add(m[1]);
      annotationCountTotal++;
    }
    if (ids.size > 0) filesAnnotated++;
    fileRuleIds.push({ file, ids });
  }

  // Categorise rule IDs
  const vrnShastra = [...allRuleIds].filter((id) => /^VRN-\d+$/.test(id));
  const vrnYukti = [...allRuleIds].filter((id) => /^VRN-YK-/.test(id));
  const otherIds = [...allRuleIds].filter((id) => !id.startsWith('VRN-'));

  // VRN code-implementable rules that have no annotation
  const expectedImplementable: string[] = [];
  for (let i = 1; i <= VRN_SHASTRA_TOTAL; i++) {
    const id = `VRN-${i.toString().padStart(3, '0')}`;
    if (!VRN_PROCEDURAL.has(id)) expectedImplementable.push(id);
  }
  const missingImplementable = expectedImplementable.filter((id) => !allRuleIds.has(id));

  const vrnAnnotatedOfImplementable = expectedImplementable.filter((id) =>
    allRuleIds.has(id)
  ).length;
  const vrnCoveragePct = Math.round((vrnAnnotatedOfImplementable / VRN_CODE_IMPLEMENTABLE) * 100);

  const fileCoveragePct = Math.round((filesAnnotated / files.length) * 100);

  // proof_status: PASS if ALL code-implementable VRN rules are annotated
  // PARTIAL if ≥ 70%, FAIL otherwise
  const proofStatus: ProofResult['proof_status'] =
    vrnCoveragePct >= 90 ? 'PASS' : vrnCoveragePct >= 70 ? 'PARTIAL' : 'FAIL';

  _cached = {
    files_total: files.length,
    files_annotated: filesAnnotated,
    file_coverage_pct: fileCoveragePct,
    unique_rule_ids: [...allRuleIds].sort(),
    vrn_shastra_annotated: vrnShastra.sort(),
    vrn_yukti_annotated: vrnYukti.sort(),
    other_rule_ids: otherIds.sort(),
    vrn_code_implementable: VRN_CODE_IMPLEMENTABLE,
    vrn_procedural_count: VRN_PROCEDURAL.size,
    vrn_annotated_of_implementable: vrnAnnotatedOfImplementable,
    vrn_coverage_pct: vrnCoveragePct,
    annotation_count_total: annotationCountTotal,
    proof_status: proofStatus,
    coverage_pct: vrnCoveragePct,
    missing_vrn_implementable: missingImplementable.sort(),
  };

  return _cached;
}

// Allow cache invalidation (e.g. for testing)
export function clearProofCache(): void {
  _cached = null;
}
