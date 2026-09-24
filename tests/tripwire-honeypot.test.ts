// SPDX-License-Identifier: AGPL-3.0-only
// Agent Tripwire honeypot tools (AGT-018), both outcomes forced: a honeypot touch trips the
// wire at WATCH (never blocks/kills); a normal tool is clean; and the external-only invariant
// holds (a honeypot leaking into an owned mask is caught). @rule:guards-assert-both-outcomes
import { describe, it, expect } from "bun:test";
import {
  HONEYPOT_TOOLS, isHoneypotTool, tripwireVerdict, assertHoneypotsExternalOnly,
} from "../src/tripwire/honeypot";

describe("honeypot tripwire (AGT-018)", () => {
  it("a call to a honeypot tool trips the wire at the WATCH stage (evidence, not a kill)", () => {
    for (const t of HONEYPOT_TOOLS) {
      const v = tripwireVerdict(t.name);
      expect(v.tripped).toBe(true);
      expect(v.stage).toBe("watch"); // never quarantine/revoke on a single touch
    }
  });

  it("a normal tool call does not trip the wire", () => {
    for (const name of ["Read", "Bash", "Edit", "ankr_codex_lookup", "SELECT"]) {
      expect(isHoneypotTool(name)).toBe(false);
      expect(tripwireVerdict(name).tripped).toBe(false);
    }
  });

  it("AGT-018 external-only invariant: no honeypot name may be in an owned capability set", () => {
    // An owned agent's real capabilities — honeypots must be absent by construction.
    const owned = ["read_service_status", "run_migration_dev", "list_orders", "Bash", "Read"];
    expect(assertHoneypotsExternalOnly(owned).ok).toBe(true);

    // A honeypot leaked into the internal domain is a violation the invariant catches.
    const leaked = [...owned, "grant_admin_scope"];
    const r = assertHoneypotsExternalOnly(leaked);
    expect(r.ok).toBe(false);
    expect(r.violations).toContain("grant_admin_scope");
  });
});
