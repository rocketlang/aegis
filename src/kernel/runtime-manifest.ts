// SPDX-License-Identifier: AGPL-3.0-only
//
// runtime-manifest — the published reference, and the offline comparator that checks a
// device against it.
//
// This is the piece the rest of the work was substrate for. Everything it consumes was
// measured first rather than assumed:
//
//   progTag       the kernel's own digest of the loaded program. Stable across build
//                 hosts (measured), so it can be published in advance. Attests the
//                 MECHANISM.
//   policyDigest  compiled from the service's declaration, never hand-authored.
//                 Attests the POLICY — because the tag does not cover the maps, and two
//                 programs with identical bytecode and different allowlists share a tag.
//   voucher       what binds this identity to a device, named rather than implied.
//
// THE COMPARATOR'S TWO RULES, both learned the hard way this week:
//
//   1. An absent field is a FAILED check, never a skipped one. A verifier that notes a
//      missing value and carries on reports success for evidence it never saw.
//   2. It states what it does NOT establish, and states it MECHANICALLY — derived from
//      the voucher, not written by hand — so the ceiling cannot drift away from the
//      evidence while the prose stays reassuring.
//
// Pure. No filesystem, no network, no clock. A comparator that needs to reach anything
// is not an offline comparator.

export const MANIFEST_SCHEMA = "ankr-runtime-manifest-v1";
export const RECEIPT_SCHEMA = "ankr-launch-receipt-v1";

/** Published in advance, before anyone asks. Signed elsewhere; this module is the shape
 *  and the comparison, not the signature. */
export interface RuntimeManifest {
  schema: typeof MANIFEST_SCHEMA;
  service: string;
  release: string;
  expect: {
    /** Kernel-computed digest of the enforcing program. */
    progTag: string;
    /** Digest of the compiled policy — see substrate-policy.policyDigest. */
    policyDigest: string;
  };
  /** XRA-R-007. Which mechanism binds the identity to a device, and therefore whose word
   *  must be trusted for the binding to hold. */
  voucher: Voucher;
}

/** The rungs of the ladder, strongest binding first. Anything else is `"unnamed"`, which
 *  the comparator refuses — an unnamed voucher is an assertion about nothing. */
export type Voucher =
  | "silicon"              // TPM, secure element, fused SoC key, PUF
  | "hypervisor"           // vTPM
  | "cloud-provider"       // instance identity document
  | "cluster"              // SPIFFE/SPIRE node + workload attestation
  | "removable-token"      // USB / PIV / smartcard — binds the CREDENTIAL, not the board
  | "registrar-statement"  // humans registered it and signed to that effect
  | "unnamed";

/** What a device presents. Read from the kernel where possible; assembled by us. */
export interface LaunchReceipt {
  schema: typeof RECEIPT_SCHEMA;
  service: string;
  release: string;
  observed: {
    progTag?: string;
    policyDigest?: string;
  };
  identity: {
    id: string;
    /** Per-boot, so the register can see two of them. */
    instance?: string;
    counter?: number;
    voucher?: Voucher;
  };
}

export interface Check {
  name: string;
  ok: boolean;
  detail: string;
}

export interface Verdict {
  service: string;
  checks: Check[];
  passed: number;
  failed: number;
  /** Mechanically derived from the voucher and from what the receipt carried. Not prose
   *  someone remembered to update. */
  doesNotEstablish: string[];
}

/**
 * What a given voucher genuinely fails to establish. Derived, never authored, so the
 * stated ceiling cannot drift away from the evidence.
 */
export function ceilingOf(v: Voucher): string[] {
  const universal = [
    "Freshness: the receipt shows a state at some time, not now. Nothing binds it to a challenge the verifier chose.",
    "That the reporting software is honest: the tag is read from the kernel, but the reading and the reporting are done by the device.",
  ];
  switch (v) {
    case "silicon":
      return [...universal,
        "Physical attack on the part itself, which is out of scope for any software check."];
    case "hypervisor":
      return [...universal,
        "That the hypervisor is uncompromised — the binding is exactly as good as the host."];
    case "cloud-provider":
      return [...universal,
        "Anything the provider cannot attest, and the key is re-issuable by them on request.",
        "DEVICE IDENTITY in the anti-cloning sense: the credential can be fetched by anything running on the instance."];
    case "cluster":
      return [...universal,
        "More than the node attestor underneath it establishes — the binding inherits that attestor's strength, whatever it is."];
    case "removable-token":
      return [...universal,
        "WHICH MACHINE this is. A removable credential binds itself, not the board it is plugged into, and it moves.",
        "That the token was not simply carried to another host — see the register's pairing report."];
    case "registrar-statement":
      return [...universal,
        "DEVICE IDENTITY at all. This is a signed statement that an enrolment happened as described; it is not replayable and cannot be checked by a stranger.",
        "Anything about cloning: a copied key produces an identical, valid receipt."];
    default:
      return [...universal, "Anything whatsoever: the voucher is unnamed."];
  }
}

/**
 * Compare a device's receipt against the published manifest. Offline, total, and loud
 * about absence.
 */
export function verifyReceipt(m: RuntimeManifest, r: LaunchReceipt): Verdict {
  const checks: Check[] = [];
  const add = (name: string, ok: boolean, detail: string) => checks.push({ name, ok, detail });

  add("manifest schema is the one this verifier understands",
      m.schema === MANIFEST_SCHEMA, `manifest schema=${m.schema ?? "(absent)"}`);
  add("receipt schema is the one this verifier understands",
      r.schema === RECEIPT_SCHEMA, `receipt schema=${r.schema ?? "(absent)"}`);

  add("the receipt is for the service the manifest describes",
      !!r.service && r.service === m.service, `manifest=${m.service} receipt=${r.service ?? "(absent)"}`);
  add("the receipt is for the release the manifest describes",
      !!r.release && r.release === m.release, `manifest=${m.release} receipt=${r.release ?? "(absent)"}`);

  // ABSENT IS A FAILURE. The two lines below are the whole lesson of the week: a
  // verifier that skips what it cannot find reports success for evidence it never saw.
  if (r.observed?.progTag === undefined) {
    add("the enforcing program's kernel tag matches the published reference",
        false, "ABSENT from the receipt — not skipped, FAILED: nothing attests the mechanism");
  } else {
    add("the enforcing program's kernel tag matches the published reference",
        r.observed.progTag === m.expect.progTag,
        `expected ${m.expect.progTag} observed ${r.observed.progTag}`);
  }

  if (r.observed?.policyDigest === undefined) {
    add("the enforced policy matches the published reference",
        false, "ABSENT from the receipt — not skipped, FAILED: the tag alone says nothing about the rules");
  } else {
    add("the enforced policy matches the published reference",
        r.observed.policyDigest === m.expect.policyDigest,
        `expected ${m.expect.policyDigest} observed ${r.observed.policyDigest}`);
  }

  // XRA-R-007: a receipt must name its voucher, and it must be the one that was
  // published. A device claiming a STRONGER binding than the manifest declares is the
  // interesting failure, not a rounding error.
  const rv = r.identity?.voucher;
  if (rv === undefined) {
    add("the receipt names its voucher", false, "ABSENT — an identity claim with nothing behind it");
  } else if (rv === "unnamed") {
    add("the receipt names its voucher", false, "voucher is 'unnamed' — refused");
  } else {
    add("the receipt names its voucher", true, `voucher=${rv}`);
    add("the voucher is the one the manifest published",
        rv === m.voucher, `manifest=${m.voucher} receipt=${rv}`);
  }

  add("the receipt carries an instance value, so duplication can be seen",
      !!r.identity?.instance, r.identity?.instance ? `instance=${r.identity.instance}`
                                                   : "ABSENT — two of these could not be told apart");

  const failed = checks.filter(c => !c.ok).length;
  return {
    service: m.service,
    checks,
    passed: checks.length - failed,
    failed,
    doesNotEstablish: ceilingOf(rv && rv !== "unnamed" ? rv : "unnamed"),
  };
}

/** Human-readable, and it prints the ceiling even on a clean run — especially then. */
export function formatVerdict(v: Verdict): string {
  const lines = v.checks.map(c => `  ${c.ok ? "ok  " : "FAIL"}  ${c.name}\n          ${c.detail}`);
  lines.push("", `  ${v.passed} passed, ${v.failed} failed`, "", "  What a clean run here does NOT establish:");
  for (const l of v.doesNotEstablish) lines.push(`    · ${l}`);
  return lines.join("\n");
}
