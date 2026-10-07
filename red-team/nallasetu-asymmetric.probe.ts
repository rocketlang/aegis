// SPDX-License-Identifier: AGPL-3.0-only
// aegis red-team — NALLASETU shared-HMAC → forgery + repudiation (review finding, 2026-10-08).
//
// Before: attestations were signed with HMAC-SHA256 over a SHARED secret held in the registry — so
// either party, and whoever held the registry, could forge the other's attestation, and neither
// could prove who signed (repudiation). An A & B capability intersection is only sound if a
// signature proves A really is A.
//
// After (hard cutover): each agent signs with its OWN Ed25519 private key; the verifier (and the
// registry) holds only the PUBLIC key. This probe drives the real crypto from the published package
// source and proves the two properties the review named. Hermetic — no DB, no network.
//
// GAP = forgery or repudiation still possible. Exit 0 when both are closed.
// Runs against repo source (public): packages/nallasetu/src/crypto.ts.
import { generateAgentKeypair, signAttest, verifyAttest, generateNonce } from '../packages/nallasetu/src/crypto.js';

let gaps = 0;
const SAFE = (id: string, ok: boolean, detail: string) => { console.log(`  [${ok ? 'safe' : 'GAP '}] ${id} — ${detail}`); if (!ok) gaps++; };

const base = (agent_id: string) => ({
  agent_id, trust_mask: 0x0F, mask_vocabulary: 'ankr-bitmask-v1', grade: 'B' as const,
  format: 'ankr-hmudrika-v1', issued_at: new Date().toISOString(),
  expires_at: new Date(Date.now() + 60_000).toISOString(), nonce: generateNonce(), public_key_id: `key-${agent_id}-v0`,
});

const alice = generateAgentKeypair();
const mallory = generateAgentKeypair();

// 1) a real attestation verifies under the signer's own public key
// (one base object — base() mints a fresh nonce/timestamp each call, so sign and verify the SAME one)
const aliceBase = base('alice');
const real = { ...aliceBase, signature: signAttest(aliceBase as any, alice.privateKey) };
SAFE('a genuine attestation verifies', verifyAttest(real as any, alice.publicKey) === true,
  "alice's badge, signed with alice's seal, checks out against alice's public key");

// 2) NO FORGERY — a party holding only the registry (alice's PUBLIC key) cannot mint as alice
let forged = false;
const b = base('alice');
for (const k of [mallory.privateKey, mallory.publicKey, alice.publicKey]) {
  try { if (verifyAttest({ ...b, signature: signAttest(b as any, k) } as any, alice.publicKey)) forged = true; } catch { /* can't even sign with a public key — good */ }
}
SAFE('no forgery from the public key', forged === false,
  "nothing you can sign with alice's PUBLIC key (or your own) verifies as alice — the registry cannot forge");

// 3) NON-REPUDIATION — alice's signature verifies ONLY under alice's key, so she can't disown it
const onlyAlice = verifyAttest(real as any, alice.publicKey) === true && verifyAttest(real as any, mallory.publicKey) === false;
SAFE('non-repudiation', onlyAlice,
  "alice's attestation verifies under alice's public key and no other — she cannot later claim someone else signed it");

// 4) a captured attestation cannot be escalated (tamper the mask) or extended (tamper the TTL)
SAFE('captured attestation cannot be escalated', verifyAttest({ ...real, trust_mask: 0xFFFF } as any, alice.publicKey) === false,
  'flip trust_mask on a signed badge → signature breaks');
SAFE('captured attestation cannot be extended', verifyAttest({ ...real, expires_at: new Date(Date.now() + 8.64e7).toISOString() } as any, alice.publicKey) === false,
  'extend expires_at on a signed badge → signature breaks');

console.log(`\n  nallasetu-asymmetric: ${gaps} gap(s)${gaps === 0 ? ' — forgery + repudiation closed ✓' : ' (RED until fixed)'}`);
process.exit(gaps > 0 ? 1 : 0);
