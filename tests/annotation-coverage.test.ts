// SPDX-License-Identifier: AGPL-3.0-only
// BMI-T014: what counts as an enforcement point, and when it is annotated (2026-10-29).
import { describe, test, expect } from "bun:test";
import { scanText, WINDOW } from "../scripts/annotation-coverage";

describe("annotation coverage", () => {
  test("refusals, blocks, holds and hook blocks are points", () => {
    const src = [
      'return { verdict: "REFUSE", detail: "x" };',
      'return { allowed: false, rule: "KAV-007" };',
      'return { verdict: "PERMIT", ask: true, detail: "y" };',
      'process.exit(2);',
      'const r = { action: "BLOCK" };',
    ].join("\n");
    expect(scanText("f.ts", src).length).toBe(5);
  });

  test("types, unions and comments are not points", () => {
    const src = [
      'type V = "PERMIT" | "REFUSE";',
      'verdict: "PERMIT" | "REFUSE" | "UNKNOWN";',
      '// return { verdict: "REFUSE" }',
      ' * allowed: false when the list is empty',
      'interface G { allowed: boolean; }',
      'return { verdict: "PERMIT", detail: "ok" };',
    ].join("\n");
    expect(scanText("f.ts", src).length).toBe(0);
  });

  test(`annotated when @rule: is on the line or within ${WINDOW} lines above; not beyond`, () => {
    const near = ['// @rule:KAV-007 tool allow-list', ...Array(WINDOW - 1).fill("x();"), 'return { allowed: false };'].join("\n");
    expect(scanText("f.ts", near)[0].annotated).toBe(true);
    const far = ['// @rule:KAV-007 tool allow-list', ...Array(WINDOW + 1).fill("x();"), 'return { allowed: false };'].join("\n");
    expect(scanText("f.ts", far)[0].annotated).toBe(false);
    expect(scanText("f.ts", 'process.exit(2); // @rule:SHD-001')[0].annotated).toBe(true);
  });

  test("cited (wider): a law: field or a refusal text that starts with a rule id, without @rule:", () => {
    const p = scanText("f.ts", ['{ id: "ANU-I-013.cap", law: "ASG-003",', '  check: () => ({ verdict: "REFUSE", detail: "over the cap" }) }'].join("\n"))[0];
    expect([p.annotated, p.cited]).toEqual([false, true]);
    expect(scanText("f.ts", 'return { verdict: "REFUSE", detail: "ASG-004: no quote" };')[0].cited).toBe(true);
    expect(scanText("f.ts", 'return { verdict: "REFUSE", detail: "no quote" };')[0].cited).toBe(false);
  });
});

