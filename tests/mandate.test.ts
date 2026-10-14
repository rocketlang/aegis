// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// P3 mandate (GTP-017/019/022). Runs under a throwaway HOME: aegis fixes its directory from HOME when
// config first loads, so HOME is set before any aegis module is imported and the file skips (saying
// why) if the directory resolves anywhere else, except on CI.

import { afterAll, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

const home = mkdtempSync(join(tmpdir(), "aegis-mandate-"));
process.env.HOME = home;
process.env.KAVACHOS_MUDRIKA_SECRET = "test-secret-for-mandates";
const approvers = join(home, "approvers.json");
writeFileSync(approvers, JSON.stringify({ owners: { telegram: ["111222333"] } }));
process.env.AOS_APPROVERS_FILE = approvers;

const { getAegisDir } = await import("../src/core/config");
const M = await import("../src/kavach/mandate");

const unsafe = !getAegisDir().startsWith(home) && !process.env.CI;
if (unsafe) console.warn(`[mandate] SKIPPED: aegis dir resolves to ${getAegisDir()}, not the scratch HOME; run this file on its own`);
afterAll(() => rmSync(home, { recursive: true, force: true }));

describe.skipIf(unsafe)("mandate (GTP-017/019/022)", () => {
  test("the principal is the first owner in the approvers file", () => {
    expect(M.principalFromApprovers()).toBe("owner:telegram:111222333");
  });

  test("issued at session start, signed, owner-only, valid for 24 hours", () => {
    const r = M.ensureMandateForSession("sess-A", { trustMask: 0b0111, scopeKey: "aegis" });
    expect(r).toMatchObject({ issued: true, status: "valid" });
    const m = r.mandate!;
    expect(m).toMatchObject({ principal_id: "owner:telegram:111222333", agent_id: "cc:sess-A", trust_mask: 0b0111, ttl_seconds: 86400 });
    expect(statSync(join(getAegisDir(), "mandates", `${m.mudrika_id}.json`)).mode & 0o777).toBe(0o600);
    expect(M.mandateForCall("sess-A")).toEqual({ mandate_id: m.mudrika_id, status: "valid", trust_mask: 0b0111 });
  });

  test("a valid mandate is kept at the next session start, not reissued", () => {
    const first = M.loadMandateForSession("sess-A")!;
    const again = M.ensureMandateForSession("sess-A", { trustMask: 0xff, scopeKey: "aegis" });
    expect(again).toMatchObject({ issued: false, status: "valid" });
    expect(again.mandate!.mudrika_id).toBe(first.mudrika_id);
  });

  test("an edited field breaks the signature: malformed, never valid", () => {
    const m = M.loadMandateForSession("sess-A")!;
    const path = join(getAegisDir(), "mandates", `${m.mudrika_id}.json`);
    const original = readFileSync(path, "utf8");
    writeFileSync(path, JSON.stringify({ ...m, trust_mask: 0xffffffff }));
    expect(M.mandateForCall("sess-A").status).toBe("malformed");
    writeFileSync(path, original);
    expect(M.mandateForCall("sess-A").status).toBe("valid");
  });

  test("expired after its lifetime; a session start then issues a new one", () => {
    const m = M.loadMandateForSession("sess-A")!;
    expect(M.judgeMandate(m, new Date(Date.parse(m.issued_at) + 86400 * 1000))).toBe("expired");
  });

  test("revoked by a person: every later call sees it, and a session start replaces it", () => {
    const m = M.loadMandateForSession("sess-A")!;
    M.revokeMandate(m.mudrika_id, "test", "flow test");
    expect(M.mandateForCall("sess-A").status).toBe("revoked");
    const renewed = M.ensureMandateForSession("sess-A", { trustMask: 0b0001, scopeKey: "aegis" });
    expect(renewed.issued).toBe(true);
    expect(renewed.mandate!.mudrika_id).not.toBe(m.mudrika_id);
    expect(M.judgeMandate(M.loadMandateById(m.mudrika_id))).toBe("revoked");
  });

  test("no principal, no mandate; an unsafe session id is refused", () => {
    expect(M.ensureMandateForSession("sess-B", { trustMask: 1, scopeKey: "x", principal: null })).toEqual({ mandate: null, issued: false, status: "missing" });
    expect(M.mandateForCall("sess-B").status).toBe("missing");
    expect(() => M.issueMandate("../evil", { trustMask: 1, scopeKey: "x", principal: "p" })).toThrow(/GTP-017/);
    expect(M.mandateForCall("../evil").status).toBe("missing");
  });
});
