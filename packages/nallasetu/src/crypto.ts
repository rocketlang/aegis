// SPDX-License-Identifier: AGPL-3.0-only
// Nallasetu — Cryptographic primitives
// @rule:NLS-002 signature verifiability — HMAC-SHA256 against registered shared secret
// @rule:NLS-005 no unknown format acceptance

import { createHmac, createHash, randomBytes } from "crypto";
import type { AttestOffer } from "./types";

export function generateNonce(): string {
  return randomBytes(32).toString("hex");
}

export function generateSessionId(): string {
  return "NLS-" + randomBytes(6).toString("hex").toUpperCase();
}

// Canonical payload: deterministic ordering for consistent HMAC input
function canonicalAttest(offer: Omit<AttestOffer, "signature">): string {
  return JSON.stringify({
    agent_id: offer.agent_id,
    trust_mask: offer.trust_mask,
    grade: offer.grade,
    format: offer.format,
    issued_at: offer.issued_at,
    expires_at: offer.expires_at,
    nonce: offer.nonce,
    public_key_id: offer.public_key_id,
  });
}

export function signAttest(offer: Omit<AttestOffer, "signature">, secret: string): string {
  return createHmac("sha256", secret).update(canonicalAttest(offer)).digest("base64");
}

export function verifyAttest(offer: AttestOffer, secret: string): boolean {
  const expected = signAttest(offer, secret);
  // Constant-time comparison
  const a = Buffer.from(expected, "base64");
  const b = Buffer.from(offer.signature, "base64");
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
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
