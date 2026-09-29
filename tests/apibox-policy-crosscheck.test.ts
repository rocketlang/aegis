// SPDX-License-Identifier: AGPL-3.0-only
// @rule:FP-016 — two implementations of one compile is how drift starts. This is the
// check that makes "drift = compiler bug" falsifiable rather than a promise.
//
// ApiBox is the COMPILER OF RECORD: it projects the policy face from the codex the same
// way it projects rest/graphql/mcp. aegis keeps its own compileEgress for the offline
// and edge path, where reaching a compiler service is exactly what must not be required.
// Two implementations therefore exist on purpose — and the canonical encoding they share
// is the part most likely to diverge quietly, so it is asserted against a real artefact.
import { describe, it, expect } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { policyDigest, driftAgainst, inAgreement, type AllowEntry } from "../src/kernel/substrate-policy";
import { sha256 } from "../src/kernel/merkle-tree";

const face = JSON.parse(readFileSync(join(import.meta.dir, "fixtures/apibox-policy-face-ankr-bfc.json"), "utf8"));

describe("ApiBox policy face ↔ aegis substrate-policy", () => {
  it("the fixture is a real compiled artefact, not a hand-written one", () => {
    expect(face.schema).toBe("apibox-policy-face-v1");
    expect(face.egress.length).toBeGreaterThan(0);
    expect(face.digest).toMatch(/^[0-9a-f]{64}$/);
  });

  it("aegis recomputes ApiBox's digest EXACTLY — the canonical encoding agrees", () => {
    expect(policyDigest(face.egress as AllowEntry[], sha256)).toBe(face.digest);
  });

  it("the agreement is not vacuous — a changed note changes the digest on both sides", () => {
    const tweaked = face.egress.map((e: AllowEntry, i: number) =>
      i === 0 ? { ...e, note: e.note + " (edited)" } : e);
    expect(policyDigest(tweaked, sha256)).not.toBe(face.digest);
  });

  it("order does not matter, as a published reference requires", () => {
    const reversed = [...face.egress].reverse();
    expect(policyDigest(reversed as AllowEntry[], sha256)).toBe(face.digest);
  });

  it("a device enforcing exactly the compiled face is in agreement", () => {
    const enforced = face.egress.map((e: AllowEntry) => ({ host: e.host, port: e.port }));
    expect(inAgreement(driftAgainst(face.egress as AllowEntry[], enforced))).toBe(true);
  });

  it("a device reaching something the declaration does not name is caught", () => {
    const enforced = [...face.egress.map((e: AllowEntry) => ({ host: e.host, port: e.port })),
                      { host: "10.0.0.9", port: 22 }];
    const d = driftAgainst(face.egress as AllowEntry[], enforced);
    expect(d.undeclared).toEqual([{ host: "10.0.0.9", port: 22 }]);
  });

  it("UNRESOLVED dependencies are carried in the artefact, not silently absent", () => {
    // ankr-bfc declares five dependencies; two cannot be placed by the port authority.
    // The artefact must say so, or a reader would believe the allowlist is complete.
    expect(face.unresolved.length).toBeGreaterThan(0);
    for (const u of face.unresolved) expect(u.reason).toBeTruthy();
  });

  it("an unresolved dependency did NOT quietly become an allow entry", () => {
    const names = new Set(face.unresolved.map((u: any) => u.name));
    for (const e of face.egress) expect(names.has(e.note.replace("depends_on ", ""))).toBe(false);
  });
});
