// SPDX-License-Identifier: AGPL-3.0-only
// @rule:FP-014 — the allowlist is a COMPILED VIEW of the declaration, never hand-authored.
import { describe, it, expect } from "bun:test";
import { compileEgress, driftAgainst, inAgreement, policyDigest,
         type CodexLike, type Resolver } from "../src/kernel/substrate-policy";
import { sha256 } from "../src/kernel/merkle-tree";

const fleet: Record<string, { host: string; port: number }> = {
  "ai-proxy":       { host: "127.0.0.1", port: 4444 },
  "ankr-eon":       { host: "127.0.0.1", port: 4101 },
  "complymitra-api":{ host: "127.0.0.1", port: 4102 },
};
const resolve: Resolver = n => fleet[n] ?? null;

describe("the allowlist is the declaration", () => {
  it("compiles depends_on into exactly those endpoints and no others", () => {
    const codex: CodexLike = { service: "ankr-bfc", depends_on: ["ai-proxy", "ankr-eon"] };
    const r = compileEgress(codex, resolve);
    expect(r.allow.map(a => `${a.host}:${a.port}`)).toEqual(["127.0.0.1:4444", "127.0.0.1:4101"]);
    expect(r.allow.every(a => a.source === "depends_on")).toBe(true);
    expect(r.unresolved).toHaveLength(0);
  });

  it("an empty declaration compiles to an empty allowlist — declaring nothing means reaching nothing", () => {
    expect(compileEgress({ service: "s", depends_on: [] }, resolve).allow).toHaveLength(0);
    expect(compileEgress({ service: "s" }, resolve).allow).toHaveLength(0);
  });

  it("an unresolvable dependency is SURFACED, never silently dropped", () => {
    const r = compileEgress({ service: "s", depends_on: ["ai-proxy", "ghost-svc"] }, resolve);
    expect(r.allow).toHaveLength(1);
    expect(r.unresolved).toEqual([{ name: "ghost-svc", reason: expect.stringContaining("could not place it") }]);
  });

  it("de-duplicates two dependencies that land on one endpoint", () => {
    const dup: Resolver = () => ({ host: "127.0.0.1", port: 4444 });
    const r = compileEgress({ service: "s", depends_on: ["a", "b", "c"] }, dup);
    expect(r.allow).toHaveLength(1);
  });
});

describe("external holes must justify themselves", () => {
  it("an external endpoint WITH a reason compiles, carrying the reason", () => {
    const r = compileEgress({ service: "s", external_egress: [
      { host: "pki.example.test", port: 443, why: "fetch the manufacturer root at enrolment" } ] }, resolve);
    expect(r.allow[0].source).toBe("external_egress");
    expect(r.allow[0].note).toMatch(/manufacturer root/);
  });

  it("an external endpoint with NO reason is refused at compile time", () => {
    for (const why of ["", "   "]) {
      const r = compileEgress({ service: "s", external_egress: [{ host: "x.test", port: 443, why }] }, resolve);
      expect(r.allow).toHaveLength(0);
      expect(r.unresolved[0].reason).toMatch(/no stated reason/);
    }
  });
});

describe("drift — a mismatch is a compiler bug, and must be falsifiable", () => {
  const compiled = compileEgress({ service: "s", depends_on: ["ai-proxy", "ankr-eon"] }, resolve).allow;

  it("agreement is agreement", () => {
    const d = driftAgainst(compiled, [{ host: "127.0.0.1", port: 4444 }, { host: "127.0.0.1", port: 4101 }]);
    expect(inAgreement(d)).toBe(true);
  });

  it("catches an endpoint enforced but NOT declared — the dangerous direction", () => {
    const d = driftAgainst(compiled, [
      { host: "127.0.0.1", port: 4444 }, { host: "127.0.0.1", port: 4101 },
      { host: "10.0.0.9", port: 22 },
    ]);
    expect(d.undeclared).toEqual([{ host: "10.0.0.9", port: 22 }]);
    expect(inAgreement(d)).toBe(false);
  });

  it("catches an endpoint declared but NOT enforced — the agent is denied what the tree grants", () => {
    const d = driftAgainst(compiled, [{ host: "127.0.0.1", port: 4444 }]);
    expect(d.unenforced.map(u => u.port)).toEqual([4101]);
    expect(inAgreement(d)).toBe(false);
  });

  it("reports BOTH directions at once rather than stopping at the first", () => {
    const d = driftAgainst(compiled, [{ host: "127.0.0.1", port: 4444 }, { host: "10.0.0.9", port: 22 }]);
    expect(d.undeclared).toHaveLength(1);
    expect(d.unenforced).toHaveLength(1);
  });
});

describe("policy digest — the value a manifest publishes", () => {
  const a = compileEgress({ service: "s", depends_on: ["ai-proxy", "ankr-eon"] }, resolve).allow;
  const b = compileEgress({ service: "s", depends_on: ["ankr-eon", "ai-proxy"] }, resolve).allow;

  it("does not depend on the order the allowlist was written in", () => {
    expect(a.map(x => x.port)).not.toEqual(b.map(x => x.port));   // genuinely different order
    expect(policyDigest(a, sha256)).toBe(policyDigest(b, sha256));
  });

  it("changes when an endpoint is added", () => {
    const c = compileEgress({ service: "s", depends_on: ["ai-proxy", "ankr-eon", "complymitra-api"] }, resolve).allow;
    expect(policyDigest(c, sha256)).not.toBe(policyDigest(a, sha256));
  });

  it("changes when only the stated REASON changes — same endpoints, different policy", () => {
    const one = compileEgress({ service: "s", external_egress: [{ host: "x.test", port: 443, why: "enrolment" }] }, resolve).allow;
    const two = compileEgress({ service: "s", external_egress: [{ host: "x.test", port: 443, why: "telemetry" }] }, resolve).allow;
    expect(one[0].port).toBe(two[0].port);
    expect(policyDigest(one, sha256)).not.toBe(policyDigest(two, sha256));
  });
});
