// SPDX-License-Identifier: AGPL-3.0-only
// Batch 100 — GNT-001 Trust Mask Inheritance Verification
//
// Verifies that the genetic trust inheritance rules are correctly implemented:
//   GNT-001: child.trust_mask = parent.trust_mask & requested_mask (never union)
//   GNT-002: lineage verification at session start catches mask overflow
//
// Run: bun /root/aegis/scripts/batch100-gnt-001-trust-inheritance.ts

import { computeChildMask, verifyLineage, formatGnt001Log, formatGnt002Log } from "../src/kavach/genetic-trust";

interface Check {
  label: string;
  pass: boolean;
  detail?: string;
}

const checks: Check[] = [];

function check(label: string, pass: boolean, detail?: string): void {
  checks.push({ label, pass, detail });
  const icon = pass ? "✅" : "❌";
  console.log(`${icon} ${label}${detail ? ` — ${detail}` : ""}`);
}

// ── GNT-001 tests ─────────────────────────────────────────────────────────────

console.log("\n── GNT-001: computeChildMask ──────────────────────────────────────────────\n");

{
  // Standard case: child asks for full inheritance, parent is the ceiling
  const parent = 0b00001111; // bits 0-3 set
  const r = computeChildMask(parent);
  check(
    "GNT-001 full inheritance: child gets exactly parent mask",
    r.child_mask === parent,
    `child=0x${r.child_mask.toString(16)} parent=0x${parent.toString(16)}`,
  );
}

{
  // Child requests a subset — gets only the intersection
  const parent = 0b11111111;
  const requested = 0b00001111;
  const r = computeChildMask(parent, requested);
  check(
    "GNT-001 narrowed request: child gets requested (within parent)",
    r.child_mask === 0b00001111,
    `child=0x${r.child_mask.toString(16)} requested=0x${requested.toString(16)}`,
  );
}

{
  // Child requests bits beyond parent — gets ONLY parent's bits (AND enforces ceiling)
  const parent = 0b00001111;
  const requested = 0b11111111; // asking for more than parent has
  const r = computeChildMask(parent, requested);
  check(
    "GNT-001 elevation blocked: child cannot exceed parent mask",
    r.child_mask === 0b00001111,
    `child=0x${r.child_mask.toString(16)} vs requested=0x${requested.toString(16)}`,
  );
  check(
    "GNT-001 bits_dropped reflects clamped bits",
    r.bits_dropped === 0b11110000,
    `bits_dropped=0x${r.bits_dropped.toString(16)}`,
  );
}

{
  // Zero-capability parent: child gets nothing
  const parent = 0;
  const r = computeChildMask(parent, 0xFFFFFFFF);
  check(
    "GNT-001 zero parent: child gets zero capabilities",
    r.child_mask === 0,
    `child=0x${r.child_mask.toString(16)}`,
  );
}

{
  // Read-only parent (trust_mask=1): child is always read-only regardless of request
  const parent = 1;
  const r = computeChildMask(parent, 0xFFFFFFFF);
  check(
    "GNT-001 read-only parent: child stays read-only",
    r.child_mask === 1,
    `child=0x${r.child_mask.toString(16)}`,
  );
}

{
  // Full financial parent: verify 32-bit correctness
  const parent = 0xFFFFFFFF;
  const requested = 0xDEADBEEF;
  const r = computeChildMask(parent, requested);
  check(
    "GNT-001 full parent: child gets exactly requested (32-bit clean)",
    r.child_mask === (0xDEADBEEF >>> 0),
    `child=0x${r.child_mask.toString(16)}`,
  );
}

console.log("\n── GNT-002: verifyLineage ─────────────────────────────────────────────────\n");

{
  // Valid: child is a strict subset of parent
  const r = verifyLineage(0b00001111, 0b11111111);
  check("GNT-002 valid lineage: child ⊆ parent", r.valid, formatGnt002Log(r));
}

{
  // Valid: child equals parent (identical mask is valid subset)
  const r = verifyLineage(0b11111111, 0b11111111);
  check("GNT-002 valid: child == parent (exact equality permitted)", r.valid, formatGnt002Log(r));
}

{
  // Invalid: child has bits parent doesn't
  const r = verifyLineage(0b11111111, 0b00001111);
  check("GNT-002 MASK_OVERFLOW detected", !r.valid && r.reason === "MASK_OVERFLOW", formatGnt002Log(r));
  check(
    "GNT-002 bits_overflowed is correct",
    r.bits_overflowed === 0b11110000,
    `bits_overflowed=0x${(r.bits_overflowed ?? 0).toString(16)}`,
  );
}

{
  // Invalid: parent envelope not found
  const r = verifyLineage(0b00001111, null);
  check("GNT-002 NO_PARENT_ENVELOPE detected", !r.valid && r.reason === "NO_PARENT_ENVELOPE", formatGnt002Log(r));
}

{
  // Zero child, any parent — always valid (child claims nothing)
  const r = verifyLineage(0, 0b11111111);
  check("GNT-002 zero-capability child is always valid", r.valid);
}

// ── Log format tests ───────────────────────────────────────────────────────────

console.log("\n── Log format ─────────────────────────────────────────────────────────────\n");

{
  const r = computeChildMask(0b00001111, 0b11111111);
  const log = formatGnt001Log(r);
  const hasChild = log.includes("child_mask=");
  const hasParent = log.includes("parent=");
  const hasDropped = log.includes("bits_dropped=");
  check("GNT-001 log includes child_mask, parent, bits_dropped", hasChild && hasParent && hasDropped, log);
}

{
  const r = verifyLineage(0b00001111, 0b11111111);
  const log = formatGnt002Log(r);
  check("GNT-002 valid log includes 'lineage OK'", log.includes("lineage OK"), log);
}

{
  const r = verifyLineage(0b11111111, 0b00001111);
  const log = formatGnt002Log(r);
  check("GNT-002 overflow log includes 'MASK_OVERFLOW'", log.includes("MASK_OVERFLOW"), log);
}

// ── Result ─────────────────────────────────────────────────────────────────────

console.log("\n──────────────────────────────────────────────────────────────────────────\n");

const passed = checks.filter(c => c.pass).length;
const failed = checks.filter(c => !c.pass).length;
const verdict = failed === 0 ? "PASS" : "FAIL";

console.log(`Batch 100: ${verdict} — ${passed}/${checks.length} checks passed`);
console.log(`@rule:GNT-001  @rule:GNT-002`);

if (failed > 0) {
  console.log("\nFailed checks:");
  checks.filter(c => !c.pass).forEach(c => console.log(`  ❌ ${c.label}`));
  process.exit(1);
}

// Write audit artifact
import { writeFileSync } from "fs";
import { join } from "path";

const artifact = {
  batch: "100",
  service: "ankr-aegis",
  rule_refs: ["GNT-001", "GNT-002"],
  verdict,
  checks_passed: passed,
  checks_total: checks.length,
  timestamp: new Date().toISOString(),
  promotion_permitted: failed === 0,
};

const artifactPath = join(import.meta.dir, "../audits/batch100_gnt_trust_inheritance.json");
writeFileSync(artifactPath, JSON.stringify(artifact, null, 2));
console.log(`\nAudit artifact: ${artifactPath}`);
