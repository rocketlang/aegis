// SPDX-License-Identifier: AGPL-3.0-only
// @rule:XRA-R-011 — an absent field is a FAILED check, never a skipped one.
import { describe, it, expect } from "bun:test";
import { verifyReceipt, ceilingOf, formatVerdict, MANIFEST_SCHEMA, RECEIPT_SCHEMA,
         type RuntimeManifest, type LaunchReceipt } from "../src/kernel/runtime-manifest";

const manifest: RuntimeManifest = {
  schema: MANIFEST_SCHEMA, service: "pump-agent", release: "v1.2.0",
  expect: { progTag: "927b5c5e18d0c7ee", policyDigest: "c6c1a262098a5c74" },
  voucher: "silicon",
};
const good: LaunchReceipt = {
  schema: RECEIPT_SCHEMA, service: "pump-agent", release: "v1.2.0",
  observed: { progTag: "927b5c5e18d0c7ee", policyDigest: "c6c1a262098a5c74" },
  identity: { id: "dev-1", instance: "boot-a", counter: 1, voucher: "silicon" },
};
const nth = (v: ReturnType<typeof verifyReceipt>, frag: string) =>
  v.checks.find(c => c.name.includes(frag))!;

describe("a matching device", () => {
  it("passes every check", () => {
    const v = verifyReceipt(manifest, good);
    expect(v.failed).toBe(0);
    expect(v.passed).toBe(v.checks.length);
  });

  it("STILL prints what it does not establish", () => {
    // The most important property of a clean run: it must not read as unqualified.
    const v = verifyReceipt(manifest, good);
    expect(v.doesNotEstablish.length).toBeGreaterThan(0);
    expect(formatVerdict(v)).toMatch(/does NOT establish/);
    expect(formatVerdict(v)).toMatch(/Freshness/);
  });
});

describe("absence is FAILURE, never a skip — the whole lesson", () => {
  it("a missing progTag FAILS and says it was absent", () => {
    const r = { ...good, observed: { policyDigest: good.observed.policyDigest } } as LaunchReceipt;
    const v = verifyReceipt(manifest, r);
    const c = nth(v, "kernel tag");
    expect(c.ok).toBe(false);
    expect(c.detail).toMatch(/ABSENT.*FAILED/);
    expect(v.failed).toBeGreaterThan(0);
  });

  it("a missing policyDigest FAILS — the tag alone attests only the mechanism", () => {
    const r = { ...good, observed: { progTag: good.observed.progTag } } as LaunchReceipt;
    const c = nth(verifyReceipt(manifest, r), "enforced policy");
    expect(c.ok).toBe(false);
    expect(c.detail).toMatch(/ABSENT/);
  });

  it("a missing instance FAILS — two of these could not be told apart", () => {
    const r = { ...good, identity: { id: "d", voucher: "silicon" as const } };
    expect(nth(verifyReceipt(manifest, r), "instance value").ok).toBe(false);
  });

  it("an empty receipt fails everything it should and reports no false pass", () => {
    const empty = { schema: RECEIPT_SCHEMA, service: "", release: "",
                    observed: {}, identity: { id: "" } } as LaunchReceipt;
    const v = verifyReceipt(manifest, empty);
    // The only things that can pass are the two schema checks — one of which is about
    // the MANIFEST and says nothing about the device. Assert the shape rather than a
    // bare count, so the test states what it means: no EVIDENCE check passed.
    const passing = v.checks.filter(c => c.ok).map(c => c.name);
    // Everything that may pass here is about the MANIFEST — its schema, and that it
    // states expectations at all. None of it says anything about the device. Assert
    // that intent rather than a substring or a count, so adding a manifest-side check
    // does not look like a regression (it did once, on 2026-09-29).
    const manifestSide = (n: string) => n.includes("schema") || n.startsWith("the manifest states");
    expect(passing.every(manifestSide)).toBe(true);
    const deviceChecks = v.checks.filter(c => !manifestSide(c.name));
    expect(deviceChecks.length).toBeGreaterThanOrEqual(5);
    expect(deviceChecks.every(c => !c.ok)).toBe(true);   // no EVIDENCE check passed
  });
});

describe("mismatches", () => {
  it("a different program tag fails", () => {
    const r = { ...good, observed: { ...good.observed, progTag: "0000000000000000" } };
    expect(nth(verifyReceipt(manifest, r), "kernel tag").ok).toBe(false);
  });

  it("the SAME tag with a DIFFERENT policy still fails — the tag does not cover the maps", () => {
    const r = { ...good, observed: { ...good.observed, policyDigest: "deadbeefdeadbeef" } };
    const v = verifyReceipt(manifest, r);
    expect(nth(v, "kernel tag").ok).toBe(true);
    expect(nth(v, "enforced policy").ok).toBe(false);
  });

  it("a receipt for another service or release fails", () => {
    expect(nth(verifyReceipt(manifest, { ...good, service: "other" }), "for the service").ok).toBe(false);
    expect(nth(verifyReceipt(manifest, { ...good, release: "v9" }), "for the release").ok).toBe(false);
  });

  it("an unknown schema fails rather than being tolerated", () => {
    expect(nth(verifyReceipt({ ...manifest, schema: "v2" as any }, good), "manifest schema").ok).toBe(false);
    expect(nth(verifyReceipt(manifest, { ...good, schema: "v2" as any }), "receipt schema").ok).toBe(false);
  });
});

describe("the voucher must be named, and must be the published one", () => {
  it("an absent voucher fails", () => {
    const r = { ...good, identity: { id: "d", instance: "b" } };
    expect(nth(verifyReceipt(manifest, r), "names its voucher").ok).toBe(false);
  });

  it("'unnamed' is refused", () => {
    const r = { ...good, identity: { ...good.identity, voucher: "unnamed" as const } };
    expect(nth(verifyReceipt(manifest, r), "names its voucher").ok).toBe(false);
  });

  it("a device claiming a DIFFERENT voucher than published fails", () => {
    const r = { ...good, identity: { ...good.identity, voucher: "registrar-statement" as const } };
    const v = verifyReceipt(manifest, r);
    expect(nth(v, "names its voucher").ok).toBe(true);        // it did name one
    expect(nth(v, "the one the manifest published").ok).toBe(false);  // the wrong one
  });
});

describe("the ceiling is derived from the voucher, not written by hand", () => {
  it("a registrar statement admits it establishes no device identity", () => {
    expect(ceilingOf("registrar-statement").join(" ")).toMatch(/not.*device identity|DEVICE IDENTITY at all/i);
  });

  it("a removable token admits it does not say WHICH MACHINE", () => {
    expect(ceilingOf("removable-token").join(" ")).toMatch(/WHICH MACHINE/);
  });

  it("silicon still admits freshness and self-reporting", () => {
    const c = ceilingOf("silicon").join(" ");
    expect(c).toMatch(/Freshness/);
    expect(c).toMatch(/reading and the reporting are done by the device/);
  });

  it("every voucher carries the two universal limits — none is exempt", () => {
    for (const v of ["silicon","hypervisor","cloud-provider","cluster","removable-token","registrar-statement","unnamed"] as const) {
      expect(ceilingOf(v).join(" ")).toMatch(/Freshness/);
      expect(ceilingOf(v).length).toBeGreaterThanOrEqual(2);
    }
  });

  it("the ceiling reported follows the RECEIPT's voucher, so a weak binding cannot hide behind a strong manifest", () => {
    const r = { ...good, identity: { ...good.identity, voucher: "registrar-statement" as const } };
    expect(verifyReceipt(manifest, r).doesNotEstablish.join(" ")).toMatch(/DEVICE IDENTITY at all/);
  });
});

describe("signing — and the key comes from OUTSIDE", () => {
  const { signManifest, verifyManifest, verifySigned, generateManifestKeypair,
          canonicalManifest } = require("../src/kernel/runtime-manifest");
  const kp = generateManifestKeypair();
  const other = generateManifestKeypair();
  const signed = signManifest(manifest, kp.privateKeyHex, "release-key-1");

  it("a genuine signature verifies under the right key", () => {
    const c = verifyManifest(signed, kp.publicKeyHex);
    expect(c.ok).toBe(true);
    expect(c.detail).toMatch(/release-key-1/);
  });

  it("it does NOT verify under a different key", () => {
    expect(verifyManifest(signed, other.publicKeyHex).ok).toBe(false);
  });

  it("an ABSENT signature FAILS — not skipped", () => {
    const c = verifyManifest({ ...signed, signature: "" }, kp.publicKeyHex);
    expect(c.ok).toBe(false);
    expect(c.detail).toMatch(/ABSENT.*FAILED/);
  });

  it("no public key supplied is a FAILURE that says the key must come from outside", () => {
    const c = verifyManifest(signed, "");
    expect(c.ok).toBe(false);
    expect(c.detail).toMatch(/must come from OUTSIDE/);
  });

  it("a malformed key is a failure, never an exception a caller could swallow", () => {
    expect(() => verifyManifest(signed, "nothex")).not.toThrow();
    expect(verifyManifest(signed, "nothex").ok).toBe(false);
  });

  it("ANY change to a signed field breaks the signature", () => {
    const tweaks = [
      { ...manifest, service: "other" },
      { ...manifest, release: "v9" },
      { ...manifest, voucher: "registrar-statement" as const },
      { ...manifest, expect: { ...manifest.expect, progTag: "0000000000000000" } },
      { ...manifest, expect: { ...manifest.expect, policyDigest: "0000000000000000" } },
    ];
    for (const t of tweaks) {
      expect(verifyManifest({ ...signed, manifest: t }, kp.publicKeyHex).ok).toBe(false);
    }
  });

  it("the canonical form does not depend on key order or formatting", () => {
    const reordered: any = { voucher: manifest.voucher, release: manifest.release,
                             expect: manifest.expect, service: manifest.service,
                             schema: manifest.schema };
    expect(canonicalManifest(reordered)).toBe(canonicalManifest(manifest));
    expect(verifyManifest({ ...signed, manifest: reordered }, kp.publicKeyHex).ok).toBe(true);
  });

  it("the manifest carries NO key material — a verifier cannot be fed its own anchor", () => {
    const blob = JSON.stringify(signed);
    expect(blob).not.toContain(kp.publicKeyHex);
    expect(blob).not.toContain(kp.privateKeyHex);
    expect(Object.keys(signed).sort()).toEqual(["keyId", "manifest", "signature"]);
  });
});

describe("verifySigned — an unsigned reference is not a reference", () => {
  const { signManifest, verifySigned, generateManifestKeypair } = require("../src/kernel/runtime-manifest");
  const kp = generateManifestKeypair();
  const other = generateManifestKeypair();
  const signed = signManifest(manifest, kp.privateKeyHex, "k1");

  it("a good signature and a good device pass together", () => {
    const v = verifySigned(signed, kp.publicKeyHex, good);
    expect(v.failed).toBe(0);
    expect(v.checks[0].name).toMatch(/signed/);
  });

  it("a BAD signature stops the comparison entirely, even with a perfect device", () => {
    const v = verifySigned(signed, other.publicKeyHex, good);
    expect(v.failed).toBe(1);
    expect(v.checks).toHaveLength(1);                 // nothing else was even compared
    expect(v.doesNotEstablish[0]).toMatch(/Everything/);
  });

  it("a good signature does not rescue a bad device", () => {
    const bad = { ...good, observed: { ...good.observed, policyDigest: "ffff" } };
    const v = verifySigned(signed, kp.publicKeyHex, bad);
    expect(v.checks[0].ok).toBe(true);
    expect(v.failed).toBe(1);
  });
});

describe("a TPM interface is not a hardware root", () => {
  const { ceilingOf } = require("../src/kernel/runtime-manifest");

  it("a firmware TPM admits it is only as good as the secure world", () => {
    const c = ceilingOf("firmware-tpm").join(" ");
    expect(c).toMatch(/secure world|TrustZone|OP-TEE/);
    expect(c).toMatch(/SoC vendor/);
  });

  it("a SOFTWARE TPM admits it has no hardware root at all", () => {
    const c = ceilingOf("software-tpm").join(" ");
    expect(c).toMatch(/ANY hardware root/);
    expect(c).toMatch(/CAN BE COPIED/);
  });

  it("software-tpm and silicon are NOT interchangeable, though both present a TPM", () => {
    // The whole risk: swtpm speaks TPM 2.0, so a reader seeing "TPM" assumes silicon.
    expect(ceilingOf("software-tpm")).not.toEqual(ceilingOf("silicon"));
    expect(ceilingOf("silicon").join(" ")).not.toMatch(/ANY hardware root/);
  });

  it("a device claiming silicon while the manifest published software-tpm is caught", () => {
    const m = { ...manifest, voucher: "software-tpm" as const };
    const r = { ...good, identity: { ...good.identity, voucher: "silicon" as const } };
    const v = verifyReceipt(m, r);
    expect(v.checks.find(c => c.name.includes("the one the manifest published"))!.ok).toBe(false);
  });

  it("every new rung still carries the two universal limits", () => {
    for (const v of ["firmware-tpm", "software-tpm"] as const) {
      expect(ceilingOf(v).join(" ")).toMatch(/Freshness/);
      expect(ceilingOf(v).join(" ")).toMatch(/reported by the device|reporting are done by the device/);
    }
  });
});
