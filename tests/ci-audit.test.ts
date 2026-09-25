// SPDX-License-Identifier: AGPL-3.0-only
// AF-T-710 — CI pipeline audit (INF-AFW-007). Both outcomes per branch: declared and
// undeclared publishes, single-line and block run: parsing, undeclared egress reported,
// uses: actions surfaced as the scoped null. And the live repo must PASS its own audit.
import { describe, it, expect } from "bun:test";
import { runLines, auditWorkflow, auditWorkflowsDir, readCiDeclarations } from "../src/kavach/ci-audit";

const DECL = { workflows: { "release.yml": { publishes: ["@x/pkg"], reason: "test" } } };

describe("runLines", () => {
  it("collects single-line and block run: steps", () => {
    const yaml = [
      "jobs:", "  a:", "    steps:",
      "      - run: bun test",
      "      - name: pub", "        run: |",
      "          echo hi",
      "          npm publish --access public",
      "      - run: echo done",
    ].join("\n");
    const lines = runLines(yaml);
    expect(lines).toContain("bun test");
    expect(lines).toContain("npm publish --access public");
    expect(lines).toContain("echo done");
    expect(lines).toContain("echo hi");
  });
});

describe("auditWorkflow", () => {
  it("a declared publish PASSes; the same publish in an undeclared workflow FAILS", () => {
    const yaml = "      - run: npm publish --access public\n";
    const declared = auditWorkflow("release.yml", yaml, DECL);
    expect(declared.publishes[0].declared).toBe(true);
    const undeclared = auditWorkflow("other.yml", yaml, DECL);
    expect(undeclared.publishes[0].declared).toBe(false);
  });

  it("reports undeclared external hosts and surfaces uses: actions as the scoped null", () => {
    const yaml = [
      "      - uses: actions/checkout@v4",
      "      - run: curl https://telemetry.example/beacon",
      "      - run: curl https://github.com/x",
    ].join("\n");
    const a = auditWorkflow("ci.yml", yaml, DECL);
    expect(a.undeclaredHosts).toEqual(["telemetry.example"]);
    expect(a.thirdPartyActions).toEqual(["actions/checkout@v4"]);
    expect(a.publishes).toEqual([]);
  });
});

describe("the aegis repo audits itself clean", () => {
  it("every publish step in .github/workflows is declared (a regression here = an undeclared outward write)", () => {
    const r = auditWorkflowsDir("/root/aegis", readCiDeclarations("/root/aegis"));
    expect(r.audits.length).toBeGreaterThanOrEqual(3);
    expect(r.undeclaredPublishes).toBe(0);
  });
});
