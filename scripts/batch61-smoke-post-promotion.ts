// Quick smoke test — post-promotion policy state verification
import {
  FREIGHTBOX_HG2B_POLICY,
  MARI8X_HG2B_POLICY,
  applyHardGate,
} from "../src/enforcement/hard-gate-policy";

const PROMOTED_ENV = "chirpee,ship-slm,chief-slm,puranic-os,pramana,domain-capture,parali-central,carbonx-backend,carbonx,freightbox,mari8x-community";
process.env.AEGIS_HARD_GATE_SERVICES = PROMOTED_ENV;

let pass = 0, fail = 0;
function chk(label: string, actual: unknown, expected: unknown): void {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  ok ? pass++ : fail++;
  console.log(`  ${ok ? "✓" : "✗"} ${label}: ${JSON.stringify(actual)}`);
}

console.log("── Batch 61 post-promotion smoke ────────────────────────────");
chk("freightbox hard_gate_enabled=true",   FREIGHTBOX_HG2B_POLICY.hard_gate_enabled, true);
chk("mari8x hard_gate_enabled=true",        MARI8X_HG2B_POLICY.hard_gate_enabled,     true);

const fb1 = applyHardGate("freightbox", "BLOCK", "ISSUE_EBL_WITHOUT_APPROVAL", "write");
chk("freightbox ISSUE_EBL_WITHOUT_APPROVAL → BLOCK", fb1.decision, "BLOCK");
chk("freightbox hard_gate_active=true",     fb1.hard_gate_active, true);

const fb2 = applyHardGate("freightbox", "ALLOW", "READ", "read");
chk("freightbox READ → ALLOW (AEG-E-002)", fb2.decision, "ALLOW");

const mx1 = applyHardGate("mari8x-community", "BLOCK", "OVERRIDE_OFFICER_CERTIFICATION", "write");
chk("mari8x OVERRIDE_OFFICER_CERTIFICATION → BLOCK", mx1.decision, "BLOCK");
chk("mari8x hard_gate_active=true",         mx1.hard_gate_active, true);

const mx2 = applyHardGate("mari8x-community", "ALLOW", "READ", "read");
chk("mari8x READ → ALLOW (AEG-E-002)",     mx2.decision, "ALLOW");

console.log(`\n${pass}/${pass + fail} PASS — promotion state verified`);
if (fail > 0) process.exit(1);
