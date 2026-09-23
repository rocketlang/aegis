// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// @rule:PRA-007 / PRA-008 — both outcomes are forced here, not just the one this host
// happens to produce. A guard only ever observed refusing is a guard nobody has seen work,
// and `measured-boot` is unreachable on a machine with no TPM, so it is driven by fixture.

import { describe, it, expect } from "bun:test";
import { mkdtempSync, writeFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { decideHostTrust, readClaim, readLivePcrs, rung, HOST_TRUST_ORDER } from "./host-trust";

const A = "aa".repeat(32);
const B = "bb".repeat(32);

describe("rung ordering", () => {
  it("orders the rungs lowest first", () => {
    expect(HOST_TRUST_ORDER).toEqual(["assumed", "measured-boot", "tpm-quote"]);
    expect(rung("assumed")).toBe(0);
    expect(rung("measured-boot")).toBe(1);
    expect(rung("tpm-quote")).toBe(2);
  });
});

describe("assumed — the honest floor", () => {
  it("returns assumed with no evidence at all, and calls it neither failure nor guess", () => {
    const r = decideHostTrust({});
    expect(r.level).toBe("assumed");
    expect(r.why).toContain("no boot reference and no readable PCRs");
    expect(r.claim_refused).toBeUndefined();
  });

  it("stays assumed when PCRs are readable but nothing was published to compare them to", () => {
    const r = decideHostTrust({ live: { "0": A } });
    expect(r.level).toBe("assumed");
    expect(r.why).toContain("no boot reference was published");
  });

  it("stays assumed when a reference exists but the host exposes no PCRs", () => {
    const r = decideHostTrust({ reference: { "0": A } });
    expect(r.level).toBe("assumed");
    expect(r.why).toContain("exposes no PCRs");
  });
});

describe("measured-boot — the rung reads up only on evidence", () => {
  it("reaches measured-boot when every published PCR agrees", () => {
    const r = decideHostTrust({ reference: { "0": A, "7": B }, live: { "0": A, "7": B } });
    expect(r.level).toBe("measured-boot");
    expect(r.why).toContain("2 PCR value(s) match");
    expect(r.claim_refused).toBeUndefined();
  });

  it("normalises case and an 0x prefix rather than failing on formatting", () => {
    const r = decideHostTrust({ reference: { "0": A.toUpperCase() }, live: { "0": `0x${A}` } });
    expect(r.level).toBe("measured-boot");
  });

  it("ignores extra live PCRs the reference does not speak to", () => {
    const r = decideHostTrust({ reference: { "0": A }, live: { "0": A, "9": B } });
    expect(r.level).toBe("measured-boot");
  });
});

describe("never rounds up", () => {
  it("does NOT reach measured-boot on a claim alone", () => {
    const r = decideHostTrust({ claim: "measured-boot" });
    expect(r.level).toBe("assumed");
    expect(r.claim_refused).toContain("claimed measured-boot");
  });

  it("does NOT reach tpm-quote on a claim alone", () => {
    const r = decideHostTrust({ claim: "tpm-quote" });
    expect(r.level).toBe("assumed");
    expect(r.claim_refused).toContain("claimed tpm-quote");
  });

  // The case an earlier draft of host-trust.ts got wrong: evidence genuinely reaches
  // measured-boot, the host claimed tpm-quote, and the reading came back clean.
  it("flags a tpm-quote claim whose evidence reaches only measured-boot", () => {
    const r = decideHostTrust({ claim: "tpm-quote", reference: { "0": A }, live: { "0": A } });
    expect(r.level).toBe("measured-boot");
    expect(r.claim_refused).toBeDefined();
    expect(r.claim_refused).toContain("reaches only measured-boot");
  });

  it("does not flag a claim the evidence actually meets", () => {
    const r = decideHostTrust({ claim: "measured-boot", reference: { "0": A }, live: { "0": A } });
    expect(r.level).toBe("measured-boot");
    expect(r.claim_refused).toBeUndefined();
  });

  it("does not flag a claim lower than what was reached", () => {
    const r = decideHostTrust({ claim: "assumed", reference: { "0": A }, live: { "0": A } });
    expect(r.level).toBe("measured-boot");
    expect(r.claim_refused).toBeUndefined();
  });
});

describe("disagreement is the loud case", () => {
  it("drops to assumed and names the differing PCR", () => {
    const r = decideHostTrust({ claim: "measured-boot", reference: { "0": A, "7": A }, live: { "0": A, "7": B } });
    expect(r.level).toBe("assumed");
    expect(r.why).toContain("does NOT agree");
    expect(r.claim_refused).toContain("PCR 7");
  });

  it("refuses loudly even when NO claim was made — a published reference that disagrees is a fact", () => {
    const r = decideHostTrust({ reference: { "0": A }, live: { "0": B } });
    expect(r.level).toBe("assumed");
    expect(r.claim_refused).toContain("investigate");
  });

  it("treats a PCR absent from the host as disagreement, not as agreement by omission", () => {
    const r = decideHostTrust({ reference: { "0": A, "7": B }, live: { "0": A } });
    expect(r.level).toBe("assumed");
    expect(r.claim_refused).toContain("PCR 7");
  });
});

describe("tpm-quote", () => {
  it("reaches tpm-quote only when a caller states a quote was verified", () => {
    const r = decideHostTrust({ quoteVerified: true });
    expect(r.level).toBe("tpm-quote");
  });

  it("a falsey quoteVerified never lifts the rung", () => {
    expect(decideHostTrust({ quoteVerified: false }).level).toBe("assumed");
    expect(decideHostTrust({ quoteVerified: undefined }).level).toBe("assumed");
  });
});

describe("probes are carried, never invented", () => {
  it("keeps caller probes and appends its own", () => {
    const r = decideHostTrust({
      reference: { "0": A },
      live: { "0": A },
      probes: [{ what: "caller", found: true, detail: "seeded" }],
    });
    expect(r.probes[0].what).toBe("caller");
    expect(r.probes.some(p => p.what === "boot reference vs live PCRs")).toBe(true);
  });
});

describe("readClaim — a declaration is an index to evidence, not evidence", () => {
  let dir: string;
  const setup = () => { dir = mkdtempSync(join(tmpdir(), "ht-")); return dir; };
  const clean = () => { try { rmSync(dir, { recursive: true, force: true }); } catch {} };

  it("treats an absent declaration as normal, not as an error", () => {
    setup();
    const c = readClaim(join(dir, "nope.json"));
    expect(c.claim).toBeUndefined();
    expect(c.probe.found).toBe(false);
    expect(c.probe.detail).toContain("nothing claimed");
    clean();
  });

  it("reports a present but unparseable declaration as a fact about the host", () => {
    setup();
    const p = join(dir, "host-trust.json");
    writeFileSync(p, "{ not json");
    const c = readClaim(p);
    expect(c.probe.found).toBe(false);
    expect(c.probe.detail).toContain("unparseable");
    clean();
  });

  it("reads an inline reference and a valid claim", () => {
    setup();
    const p = join(dir, "host-trust.json");
    writeFileSync(p, JSON.stringify({ claim: "measured-boot", pcr_reference: { "0": A } }));
    const c = readClaim(p);
    expect(c.claim).toBe("measured-boot");
    expect(c.reference).toEqual({ "0": A });
    clean();
  });

  it("drops an unrecognised claim string rather than passing it through", () => {
    setup();
    const p = join(dir, "host-trust.json");
    writeFileSync(p, JSON.stringify({ claim: "totally-trustworthy" }));
    expect(readClaim(p).claim).toBeUndefined();
    clean();
  });

  it("discards non-string reference entries instead of guessing at them", () => {
    setup();
    const p = join(dir, "host-trust.json");
    writeFileSync(p, JSON.stringify({ pcr_reference: { "1": { A: "x", B: "y" } } }));
    expect(readClaim(p).reference).toBeUndefined();
    clean();
  });

  it("loads a reference from a path and unwraps a .pcr envelope", () => {
    setup();
    const refPath = join(dir, "pcr.json");
    writeFileSync(refPath, JSON.stringify({ pcr: { "0": A } }));
    const p = join(dir, "host-trust.json");
    writeFileSync(p, JSON.stringify({ claim: "measured-boot", pcr_reference: refPath }));
    const c = readClaim(p);
    expect(c.reference).toEqual({ "0": A });
    clean();
  });

  it("does not fabricate a reference when the path is unreadable", () => {
    setup();
    const p = join(dir, "host-trust.json");
    writeFileSync(p, JSON.stringify({ claim: "measured-boot", pcr_reference: join(dir, "gone.json") }));
    const c = readClaim(p);
    expect(c.reference).toBeUndefined();
    expect(c.probe.detail).toContain("unreadable");
    // and the claim, unsupported, must not survive the decision
    expect(decideHostTrust({ claim: c.claim, reference: c.reference, live: {} }).level).toBe("assumed");
    clean();
  });
});

describe("readLivePcrs", () => {
  it("returns no PCRs and says why when the sysfs path is absent", () => {
    const { pcrs, probe } = readLivePcrs("/nonexistent/tpm/pcr-sha256");
    expect(Object.keys(pcrs)).toHaveLength(0);
    expect(probe.found).toBe(false);
    expect(probe.detail).toContain("does not exist");
  });

  it("reads numeric PCR files and ignores everything else in the directory", () => {
    const dir = mkdtempSync(join(tmpdir(), "pcr-"));
    writeFileSync(join(dir, "0"), `${A}\n`);
    writeFileSync(join(dir, "7"), `${B}\n`);
    writeFileSync(join(dir, "README"), "not a pcr");
    const { pcrs, probe } = readLivePcrs(dir);
    expect(pcrs).toEqual({ "0": A, "7": B });
    expect(probe.found).toBe(true);
    rmSync(dir, { recursive: true, force: true });
  });
});
