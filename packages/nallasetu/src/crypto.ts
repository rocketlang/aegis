// SPDX-License-Identifier: AGPL-3.0-only
// Nallasetu — Cryptographic primitives
// @rule:NLS-002 signature verifiability — ASYMMETRIC: each agent signs with its own Ed25519 private
//   key; a verifier (or the registry) holds only the public key, so it cannot forge another agent's
//   attestation, and the signer cannot repudiate its own. (Was HMAC-SHA256 over a shared secret,
//   which let either party — and the registry — forge the other; closed 2026-10-08, hard cutover.)
// @rule:NLS-005 no unknown format acceptance

import { createHash, randomBytes, generateKeyPairSync, createPrivateKey, createPublicKey, sign as edSign, verify as edVerify } from "crypto";
import type { AttestOffer } from "./types";

export function generateNonce(): string {
  return randomBytes(32).toString("hex");
}

export function generateSessionId(): string {
  return "NLS-" + randomBytes(6).toString("hex").toUpperCase();
}

/** A new per-agent seal: the private key stays with the agent, the public key goes in the registry. */
export function generateAgentKeypair(): { publicKey: string; privateKey: string } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKey: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKey: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
}

// Canonical payload: deterministic ordering for a consistent signing input. mask_vocabulary is
// signed too — the dialect a trust_mask is written in is part of what the signature commits to.
function canonicalAttest(offer: Omit<AttestOffer, "signature">): string {
  return JSON.stringify({
    agent_id: offer.agent_id,
    trust_mask: offer.trust_mask,
    mask_vocabulary: offer.mask_vocabulary,
    grade: offer.grade,
    format: offer.format,
    issued_at: offer.issued_at,
    expires_at: offer.expires_at,
    nonce: offer.nonce,
    public_key_id: offer.public_key_id,
  });
}

/** Sign with the agent's OWN private key (Ed25519). Only the holder of the seal can produce this. */
export function signAttest(offer: Omit<AttestOffer, "signature">, privateKeyPem: string): string {
  const msg = Buffer.from(canonicalAttest(offer), "utf8");
  return edSign(null, msg, createPrivateKey(privateKeyPem)).toString("base64");
}

/** Verify against the agent's PUBLIC key from the registry. The verifier holds no secret to forge with. */
export function verifyAttest(offer: AttestOffer, publicKeyPem: string): boolean {
  try {
    const { signature, ...base } = offer;
    const msg = Buffer.from(canonicalAttest(base), "utf8");
    return edVerify(null, msg, createPublicKey(publicKeyPem), Buffer.from(signature, "base64"));
  } catch {
    return false; // malformed key or signature → not verified, never throws into the gate
  }
}

export function hashCredential(fields: {
  session_id: string;
  initiator_id: string;
  responder_id: string;
  session_mask: number;
  issued_at: string;
  expires_at: string;
}): string {
  return createHash("sha256")
    .update(JSON.stringify(fields))
    .digest("hex");
}

export function hashReceipt(credentialHash: string, outcome: string): string {
  return createHash("sha256")
    .update(credentialHash + ":" + outcome)
    .digest("hex");
}

// PRAMANA-style chain hash: receipt_hash + previous_pramana_hash
export function pramanaWitness(receiptHash: string, previousHash: string): string {
  return createHash("sha256")
    .update(receiptHash + ":" + previousHash)
    .digest("hex");
}

// Policy hash: identifies the protocol version + config governing this handshake
export function policyHash(): string {
  return createHash("sha256")
    .update("nallasetu/0.1:" + (process.env.NALLASETU_RATE_LIMIT ?? "10"))
    .digest("hex")
    .slice(0, 16);
}
