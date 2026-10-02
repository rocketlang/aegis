// SPDX-License-Identifier: AGPL-3.0-only
// The refusal ledger, forced both ways through a REAL gate (check-budget, the one gate
// whose verdict depends only on an isolated database — no network, no escalation).
//
//   over budget in enforce mode → exit 2 AND one row, gate "aegis-budget"
//   over budget in alert mode   → exit 0 AND no row
//   ledger unwritable           → STILL exit 2 (the ledger can never change a verdict)
//
// What this does NOT force: a refusal by shield, spawn, destructive or chitta. Their deny
// paths need state that can escalate to a human approver, which a test must not do.
// They share the one arming point in cli/index.ts that this test proves for budget.
import { describe, it, expect } from "bun:test";
import { existsSync, readFileSync, mkdtempSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { TestHarness, dailyPeriodKey, now } from "../src/test-agents/harness.ts";
import { parseRule } from "../src/core/refusal-ledger.ts";

function overBudget(name: string, mode: "enforce" | "alert"): TestHarness {
  const h = new TestHarness(name);
  h.setup({ enforcement: { mode }, budget: { daily_limit_usd: 5 } });
  h.seedDb((db) => {
    db.run(
      "INSERT OR REPLACE INTO budget_state (period, spent_usd, limit_usd, last_updated) VALUES (?, ?, ?, ?)",
      [dailyPeriodKey(), 6.0, 5.0, now()],
    );
  });
  return h;
}

const rowsOf = (file: string) =>
  existsSync(file) ? readFileSync(file, "utf-8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : [];

describe("refusal ledger", () => {
  it("records a real refusal once, under the gate's name", async () => {
    const ledger = join(mkdtempSync(join(tmpdir(), "aegis-refusal-")), "refusals.jsonl");
    const h = overBudget("refusal-ledger-enforce", "enforce");
    try {
      const r = await h.callHook("check-budget", {}, { CLAUDE_SESSION_ID: "ledger-test-1", CLAUDE_CODE_SESSION_ID: "", AEGIS_REFUSAL_LEDGER: ledger });
      expect(r.exitCode).toBe(2);
      const rows = rowsOf(ledger);
      expect(rows.length).toBe(1);
      expect(rows[0].gate).toBe("aegis-budget");
      expect(rows[0].kind).toBe("refused");
      expect(rows[0].session).toBe("ledger-test-1");
      expect(Number.isNaN(Date.parse(rows[0].ts))).toBe(false);
    } finally { h.cleanup(); }
  });

  it("writes nothing when the gate allows", async () => {
    const ledger = join(mkdtempSync(join(tmpdir(), "aegis-refusal-")), "refusals.jsonl");
    const h = overBudget("refusal-ledger-alert", "alert");
    try {
      const r = await h.callHook("check-budget", {}, { CLAUDE_SESSION_ID: "ledger-test-2", AEGIS_REFUSAL_LEDGER: ledger });
      expect(r.exitCode).toBe(0);
      expect(rowsOf(ledger).length).toBe(0);
    } finally { h.cleanup(); }
  });

  it("still refuses when the ledger cannot be written", async () => {
    const dir = mkdtempSync(join(tmpdir(), "aegis-refusal-"));
    const plainFile = join(dir, "a-plain-file");
    writeFileSync(plainFile, "x");
    const h = overBudget("refusal-ledger-unwritable", "enforce");
    try {
      const r = await h.callHook("check-budget", {}, { CLAUDE_SESSION_ID: "ledger-test-3", AEGIS_REFUSAL_LEDGER: join(plainFile, "cannot", "exist.jsonl") });
      expect(r.exitCode).toBe(2);
    } finally { h.cleanup(); }
  });

  it("does not arm for gates that keep their own ledger, or for non-gates", () => {
    const src = readFileSync(join(import.meta.dir, "../src/cli/index.ts"), "utf-8");
    const m = src.match(/const RECORDED_GATES = \[([^\]]*)\]/);
    expect(m).not.toBeNull();
    const listed = m![1].split(",").map((s) => s.trim().replace(/"/g, "")).filter(Boolean).sort();
    expect(listed).toEqual(["check-budget", "check-chitta", "check-destructive", "check-shield", "check-spawn"]);
  });

  it("reads the rule id the gate printed", () => {
    expect(parseRule("[BMOS:expiry] Session x expired (BMOS-008) — BLOCKED")).toBe("BMOS-008");
    expect(parseRule("  Rule : INF-KAV-006")).toBe("INF-KAV-006");
    expect(parseRule("AEGIS: Weekly budget exhausted — BLOCKED")).toBeNull();
    expect(parseRule("blocked on 2026-09-30")).toBeNull();
  });
});
