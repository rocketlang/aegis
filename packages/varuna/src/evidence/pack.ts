/**
 * IACS evidence pack — three-column mapping: VRN rule + IACS UR clause + MITRE ATT&CK ICS.
 * @rule:VRN-047 Evidence pack must contain all three columns
 * @rule:P2-004  Evidence pack generated from vessel findings
 */

import { IACS_CAPABILITIES } from '../iacs/capabilities.js';
import type { IACSCapabilityResult, VesselState } from '../store/vessel.js';

export interface EvidenceEntry {
  vrn_rule: string;
  iacs_clause: string;
  mitre_technique_id: string;
  mitre_technique_name: string;
  cap_id: string;
  cap_name: string;
  finding: string | null;
  triggered: boolean;
}

// @rule:VRN-047 Build three-column evidence pack for vessel's current audit results
export function buildEvidencePack(vessel: VesselState): EvidenceEntry[] {
  const auditMap = new Map<string, IACSCapabilityResult>(
    vessel.iacs_audit.map((r) => [r.cap_id, r])
  );

  return IACS_CAPABILITIES.map((cap) => {
    const result = auditMap.get(cap.cap_id);
    const triggered = result?.status === 'FAIL' || result?.status === 'PARTIAL';
    return {
      vrn_rule: cap.rule_id,
      iacs_clause: cap.iacs_clause,
      mitre_technique_id: cap.mitre_technique_id,
      mitre_technique_name: cap.mitre_technique_name,
      cap_id: cap.cap_id,
      cap_name: cap.name,
      finding: result ? result.evidence : null,
      triggered,
    };
  });
}

// Only triggered (FAIL/PARTIAL) entries for the evidence report
export function buildTriggeredEvidencePack(vessel: VesselState): EvidenceEntry[] {
  return buildEvidencePack(vessel).filter((e) => e.triggered);
}
