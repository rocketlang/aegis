// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// attest — identify a malformed or impostor agent: prove WHO it is and WHAT it is running.
//
//   WHO  — the agent's attestation is signed by its own Ed25519 identity key; a verifier (or the
//          registry) holds only the public key, so it cannot be impersonated (the Nallasetu model).
//   WHAT — a deterministic MEASUREMENT (sha256 over a sorted manifest of its code+config files)
//          compared to a pinned BASELINE. Tampered code, a swapped config, or the wrong build → a
//          different digest → refused at the boundary.
//
// HONEST CEILING (the whole point, say it): a measurement is only as trustworthy as the thing that
// took it. An agent that measures ITSELF can report a baseline-matching digest while running tampered
// code. So the measurement must be produced OUTSIDE the agent — by the launcher, before exec, over the
// files the agent cannot change in flight — and the real root of trust is hardware/remote attestation
// (TPM/measured boot) for the measurer itself. This module is the measurer + the boundary check;
// launcher-measured integration is the next rung, hardware-root the ceiling. We refuse when there is
// no baseline (unknown is not trusted), never pass silently.

import { createHash, sign as edSign, verify as edVerify, createPrivateKey, createPublicKey, generateKeyPairSync } from "crypto";
import { readFileSync } from "fs";

export interface Measurement {
  manifest: { path: string; sha256: string }[];
  digest: string;
}

/** A new agent identity keypair. The private key stays with the agent; the public key is registered. */
export function generateIdentityKeypair(): { publicKey: string; privateKey: string } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKey: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKey: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
}

/**
 * Measure a set of files into a single digest: sha256 over a sorted [{path, sha256(content)}] manifest.
 * Deterministic and order-independent. A missing file is recorded as sha256 "MISSING" so a deleted file
 * changes the digest too. Intended to be called by the LAUNCHER over the agent's declared files, not by
 * the agent about itself.
 */
export function measureFiles(paths: string[], relativeTo?: string): Measurement {
  const manifest = [...new Set(paths)].sort().map((p) => {
    let h: string;
    try { h = createHash("sha256").update(readFileSync(p)).digest("hex"); }
    catch { h = "MISSING"; }
    return { path: relativeTo && p.startsWith(relativeTo) ? p.slice(relativeTo.length).replace(/^\/+/, "") : p, sha256: h };
  });
  const digest = createHash("sha256").update(JSON.stringify(manifest)).digest("hex");
  return { manifest, digest };
}

/** Sign a measurement digest with the agent's identity private key (binds WHAT to WHO). */
export function signMeasurement(digest: string, privateKeyPem: string): string {
  return edSign(null, Buffer.from(digest, "utf8"), createPrivateKey(privateKeyPem)).toString("base64");
}

export function verifyMeasurementSig(digest: string, sig: string, identityPublicKeyPem: string): boolean {
  try { return edVerify(null, Buffer.from(digest, "utf8"), createPublicKey(identityPublicKeyPem), Buffer.from(sig, "base64")); }
  catch { return false; }
}

export type AttestVerdict =
  | { ok: true }
  | { ok: false; kind: "no-baseline" | "identity" | "measurement"; detail: string };

/**
 * The boundary check: (1) there must be a pinned baseline (no baseline = refuse, unknown is not
 * trusted), (2) the measurement must be signed by the registered identity key (not an impostor),
 * (3) the measured digest must equal the baseline (not tampered / wrong build).
 */
export function verifyAttestation(
  measuredDigest: string,
  sig: string,
  identityPublicKeyPem: string | null,
  baselineDigest: string | null,
): AttestVerdict {
  if (!baselineDigest) return { ok: false, kind: "no-baseline", detail: "no pinned baseline for this agent — cannot attest; unknown is refused, not trusted" };
  if (!identityPublicKeyPem || !verifyMeasurementSig(measuredDigest, sig, identityPublicKeyPem)) {
    return { ok: false, kind: "identity", detail: "measurement is not signed by the registered identity key — impostor or unsigned" };
  }
  if (measuredDigest !== baselineDigest) {
    return { ok: false, kind: "measurement", detail: `code/config digest ${measuredDigest.slice(0, 12)}… does not match the pinned baseline ${baselineDigest.slice(0, 12)}… — tampered or a different build` };
  }
  return { ok: true };
}
