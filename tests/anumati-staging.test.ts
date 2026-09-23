// SPDX-License-Identifier: AGPL-3.0-only
// The observe stage: a staged invariant (ANU-I-006) reports without ever flipping the verdict,
// while enforced invariants still bite. Both outcomes forced. @rule:AF-T-103
import { describe, it, expect } from "bun:test";
import { anumati, resolveTargetDb, type ProposedAction } from "../src/kavach/anumati";

const act = (command: string): ProposedAction => ({ tool: "Bash", command, cwd: "/root", session_id: "test-staging" });

describe("ANU-I-006 runs in observe stage", () => {
  it("flags an arbitrary-SQL invocation with an unresolvable target as an OBSERVATION, not a refusal", () => {
    // env-indirection: SQL-capable, not provably read-only, no resolvable target → UNKNOWN,
    // but observe-stage, so it must appear in observations and NEVER in refusals.
    const d = anumati(act('psql -c "$LEGACY_MIGRATION_SQL"'));
    const obs = d.observations.find(o => o.id === "ANU-I-006");
    expect(obs).toBeDefined();
    expect(obs!.verdict).toBe("UNKNOWN");
    expect(d.refusals.some(r => r.id === "ANU-I-006")).toBe(false);
  });

  it("does not apply to a provably read-only invocation", () => {
    const d = anumati(act("psql -c 'SELECT 1'"));
    expect(d.results.some(r => r.id === "ANU-I-006")).toBe(false);
  });

  it("every decision carries a defined observations array", () => {
    expect(Array.isArray(anumati(act("ls -la")).observations)).toBe(true);
  });
});

describe("AF-T-106: resolveTargetDb names implicit PGDATABASE targets", () => {
  it("resolves an inline PGDATABASE=<name> assignment", () => {
    expect(resolveTargetDb("PGDATABASE=payments_prod psql -c 'SELECT 1'")).toBe("payments_prod");
  });
  it("an explicit -d still wins over PGDATABASE (psql precedence)", () => {
    expect(resolveTargetDb("PGDATABASE=x psql -d billing_dev -c 'SELECT 1'")).toBe("billing_dev");
  });
  it("PGDATABASE=$VAR does not resolve — stays null → UNKNOWN → refuse/observe", () => {
    expect(resolveTargetDb('PGDATABASE=$TARGET psql -c "$SQL"')).toBeNull();
  });
});

describe("enforce-stage invariants still set the verdict (staging did not disarm them)", () => {
  it("a write to a protected source is REFUSED (ANU-I-005), verdict REFUSE", () => {
    const d = anumati({
      tool: "Write",
      file_path: "/root/.ankr/config/databases.json",
      cwd: "/root",
      session_id: "test-staging",
    });
    expect(d.verdict).toBe("REFUSE");
    expect(d.refusals.some(r => r.id === "ANU-I-005")).toBe(true);
    expect(d.refusals.every(r => (r.stage ?? "enforce") !== "observe")).toBe(true);
  });
});
