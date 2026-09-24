// SPDX-License-Identifier: AGPL-3.0-only
// External honeypot manifest (AF-T-606, AGT-018), invariants forced: the external manifest
// advertises every honeypot with a schema; the internal-manifest guard flags a leaked
// honeypot; a honeypot call trips WATCH with an inert decoy (no secret). @rule:guards-assert-both-outcomes
import { describe, it, expect } from "bun:test";
import { externalManifest, assertInternalManifestClean, handleExternalCall } from "../src/tripwire/manifest";
import { HONEYPOT_TOOLS } from "../src/tripwire/honeypot";

describe("external honeypot manifest (AF-T-606)", () => {
  it("the external manifest advertises every honeypot tool with an input schema", () => {
    const m = externalManifest();
    expect(m.length).toBe(HONEYPOT_TOOLS.length);
    for (const t of m) {
      expect(t.name).toBeTruthy();
      expect(t.description).toBeTruthy();
      expect(t.inputSchema.type).toBe("object");
    }
  });

  it("AGT-018 guard: a clean internal manifest passes, a leaked honeypot is caught", () => {
    expect(assertInternalManifestClean([{ name: "read_status" }, { name: "list_orders" }]).ok).toBe(true);
    const r = assertInternalManifestClean([{ name: "read_status" }, { name: "grant_admin_scope" }]);
    expect(r.ok).toBe(false);
    expect(r.violations).toContain("grant_admin_scope");
  });

  it("a honeypot call trips WATCH and returns an inert decoy — no data, no fabricated secret", () => {
    const o = handleExternalCall("db_dump_all_databases");
    expect(o.isHoneypot).toBe(true);
    expect(o.event?.stage).toBe("watch");
    expect(o.response).toEqual({ status: "accepted", ref: expect.any(String) });
    // the decoy carries no token/secret/credential fields
    expect(JSON.stringify(o.response)).not.toMatch(/token|secret|password|key/i);
  });

  it("a non-honeypot name is not ours to answer here", () => {
    const o = handleExternalCall("Read");
    expect(o.isHoneypot).toBe(false);
    expect(o.response).toBeNull();
  });
});
