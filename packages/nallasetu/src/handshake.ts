// SPDX-License-Identifier: AGPL-3.0-only
// Nallasetu — Handshake Engine
// Five-primitive protocol: BRIDGE_HELLO → ATTEST_OFFER → INTERSECT_PROPOSE → SESSION_CREDENTIAL → SESSION_RECEIPT
// @rule:NLS-001 bilateral attestation — both parties must attest
// @rule:NLS-002 HMAC-SHA256 signature verifiability
// @rule:NLS-003 no bit escalation — session_mask = A & B & scope
// @rule:NLS-004 attestation format version gate
// @rule:NLS-005 no unknown format acceptance
// @rule:NLS-006 mandatory TTL — session credentials must expire
// @rule:NLS-007 bilateral revocability — either party can revoke within 1s
// @rule:NLS-008 no credential reuse — new handshake for each session
// @rule:NLS-009 post-TTL invalidity — expired credentials rejected, no grace
// @rule:NLS-010 PRAMANA-witnessed receipts
// @rule:NLS-011 immutable receipt storage — append-only
// @rule:NLS-012 mandatory SENSE events on every outcome
// @rule:NLS-013 registry-mediated key lookup
// @rule:NLS-014 registry staleness rejection
// @rule:NLS-015 per-partner rate limiting
// @rule:NLS-016 500ms latency budget
// @rule:NLS-YK-001 unknown signer → REJECT
// @rule:NLS-YK-002 zero intersection → graceful fail with diagnostic
// @rule:NLS-YK-003 scope overreach → counter-proposal
// @rule:NLS-YK-004 mid-session expiration → early termination receipt
// @rule:NLS-YK-005 clock skew → 5-minute max tolerance on issued_at
// @rule:NLS-YK-006 witness unavailable → fail session retroactively
// @rule:NLS-YK-007 forward version compatibility → attempt downgrade on minor bump
// @rule:NLS-YK-008 known-revoked partner → REJECT immediately
// @rule:NLS-YK-009 failing-grade partner → ephemeral only
// @rule:NLS-YK-010 registry offline fallback → cached key < 1hr, ephemeral only
// @rule:INF-NLS-001 non-compliant target → 500ms timeout = not Nallasetu
// @rule:INF-NLS-002 happy-path fast track → sig valid + registry + non-zero → proceed
// @rule:INF-NLS-003 vendor trust floor — HanumanG/LakshmanRekha attestations accepted
// @rule:INF-NLS-004 post-TTL fast reject — own clock, no grace
// @rule:INF-NLS-008 trivial intersection fast path — identical masks = skip negotiation round

import {
  generateNonce, generateSessionId, signAttest, verifyAttest, generateAgentKeypair,
  hashCredential, hashReceipt, pramanaWitness, policyHash,
} from "./crypto";
import {
  lookupKey, registerKey, storeSession, storePrivateKey, loadPrivateKey,
  getLastPramanaHash, appendPramanaChain,
} from "./db";
import {
  PROTOCOL_VERSION, ATTESTATION_FORMAT, MASK_VOCABULARY,
  type HandshakeRequest, type HandshakeResult,
  type AttestOffer, type IntersectPropose,
  type SessionCredential, type SessionReceipt,
} from "./types";
import { emitHandshakeSense } from "./sense";

// ── Rate limiter (NLS-015) ────────────────────────────────────────────────────

const _rateBuckets = new Map<string, { count: number; reset: number }>();
const RATE_LIMIT = parseInt(process.env.NALLASETU_RATE_LIMIT ?? "10", 10);

function checkRate(partnerId: string): boolean {
  // @rule:NLS-015 — 10 handshakes/sec per partner, excess rejected not queued
  const now = Date.now();
  const bucket = _rateBuckets.get(partnerId);
  if (!bucket || now > bucket.reset) {
    _rateBuckets.set(partnerId, { count: 1, reset: now + 1000 });
    return true;
  }
  if (bucket.count >= RATE_LIMIT) return false;
  bucket.count++;
  return true;
}

// ── TTL per session class (NLS-006) ──────────────────────────────────────────

const SESSION_TTL: Record<string, number> = {
  ephemeral:      60,
  conversational: 1800,
  autonomous:     86400,
};

// ── Responder self-registration (Customer Zero bootstrap) ─────────────────────

// A self-managed agent: generate a keypair if unknown — the PUBLIC key goes in the registry, the
// PRIVATE seal into the local keystore. Returns the private key to sign THIS agent's offer with, or
// privateKey=null for an agent whose seal this deployment does not hold (remote-registered): such an
// agent must supply its own signed attestation, the engine cannot sign on its behalf.
export function ensureResponderKey(agentId: string): { privateKey: string | null; keyId: string } {
  const row = lookupKey(agentId);
  if (!row) {
    const { publicKey, privateKey } = generateAgentKeypair();
    const keyId = `key-${agentId}-v0`;
    registerKey({
      agent_id: agentId,
      public_key: publicKey,
      public_key_id: keyId,
      trust_mask: 0xFFFF, // @rule:Bit10 — self-registered agents get limited default, not all-bits
      registered_at: new Date().toISOString(),
      source: "self",
    });
    storePrivateKey(agentId, privateKey);
    return { privateKey, keyId };
  }
  return { privateKey: loadPrivateKey(agentId), keyId: row.public_key_id };
}

// ── Main handshake engine ─────────────────────────────────────────────────────

export async function conductHandshake(req: HandshakeRequest): Promise<HandshakeResult> {
  const t0 = performance.now();
  const ph = policyHash();

  // @rule:NLS-015 rate check before any work
  if (!checkRate(req.initiator.agent_id)) {
    const result = {
      decision: "handshake_rate_limit_exceeded" as const,
      error: "Too many handshakes from this partner — retry after 1 second",
      policy_hash: ph,
      latency_ms: Math.round(performance.now() - t0),
      rule_ref: "NLS-015",
    };
    emitHandshakeSense("nallasetu.handshake.rate_limit_exceeded", {
      initiator_id: req.initiator.agent_id, responder_id: req.responder_id,
      decision: result.decision, policy_hash: ph,
      latency_ms: result.latency_ms, rule_ref: result.rule_ref,
    });
    return result;
  }

  // ── Primitive 1: BRIDGE_HELLO ─────────────────────────────────────────────
  // @rule:NLS-004 attestation format version gate
  const sessionNonce = generateNonce();
  const bridgeHello = {
    protocol_version: PROTOCOL_VERSION,
    supported_formats: [ATTESTATION_FORMAT],
    initiator_id: req.initiator.agent_id,
    timestamp: new Date().toISOString(),
    nonce: sessionNonce,
  };

  // ── Primitive 2: ATTEST_OFFER — initiator ────────────────────────────────
  // Ensure initiator has a key (auto-register if unknown — Customer Zero allows this)
  const { privateKey: initiatorPriv, keyId: initiatorKeyId } = ensureResponderKey(req.initiator.agent_id);

  // @rule:NLS-YK-008 known-revoked partner → REJECT immediately — symmetric: an initiator the
  // registry has marked revoked is refused too, not only a revoked responder. (A freshly
  // auto-registered Customer-Zero initiator is never revoked, so this never blocks the happy path.)
  const initiatorKeyRow = lookupKey(req.initiator.agent_id);
  if (initiatorKeyRow?.revoked === 1) {
    const result = {
      decision: "attestation_unverifiable" as const,
      error: `Initiator '${req.initiator.agent_id}' is revoked — NLS-YK-008`,
      policy_hash: ph,
      latency_ms: Math.round(performance.now() - t0),
      rule_ref: "NLS-YK-008",
    };
    emitHandshakeSense("nallasetu.handshake.session_failed", {
      initiator_id: req.initiator.agent_id, responder_id: req.responder_id,
      decision: result.decision, policy_hash: ph,
      latency_ms: result.latency_ms, rule_ref: result.rule_ref,
    });
    return result;
  }

  // @rule:NLS-YK-009 failing-grade initiator → ephemeral session only, no upgrade
  const initiatorGradeEarly = req.initiator.grade ?? "B";
  const isFailingGrade = initiatorGradeEarly === "F" || initiatorGradeEarly === "D";
  const sessionClass = isFailingGrade
    ? "ephemeral"
    : (req.session_class ?? "conversational");
  const ttlSeconds = SESSION_TTL[sessionClass] ?? SESSION_TTL.conversational;
  const now = new Date();
  const expiresAt = new Date(now.getTime() + ttlSeconds * 1000).toISOString();

  // The engine can only sign for an agent whose private seal it holds (NLS-002).
  if (!initiatorPriv) {
    const result = {
      decision: "attestation_unverifiable" as const,
      error: `No private key held locally for initiator '${req.initiator.agent_id}' — it must supply its own signed attestation (NLS-002)`,
      policy_hash: ph, latency_ms: Math.round(performance.now() - t0), rule_ref: "NLS-002",
    };
    emitHandshakeSense("nallasetu.handshake.attestation_unverifiable", {
      initiator_id: req.initiator.agent_id, responder_id: req.responder_id,
      decision: result.decision, policy_hash: ph, latency_ms: result.latency_ms, rule_ref: result.rule_ref, error: result.error,
    });
    return result;
  }
  const initiatorOfferBase: Omit<AttestOffer, "signature"> = {
    agent_id: req.initiator.agent_id,
    trust_mask: req.initiator.trust_mask,
    mask_vocabulary: MASK_VOCABULARY,
    grade: req.initiator.grade ?? "B",
    format: ATTESTATION_FORMAT,
    issued_at: now.toISOString(),
    expires_at: expiresAt,
    nonce: sessionNonce,
    public_key_id: initiatorKeyId,
  };
  const initiatorOffer: AttestOffer = {
    ...initiatorOfferBase,
    signature: signAttest(initiatorOfferBase, initiatorPriv),
  };

  // ── Primitive 2: ATTEST_OFFER — responder ────────────────────────────────
  // @rule:NLS-013 registry-mediated key lookup for responder
  const responderKeyRow = lookupKey(req.responder_id);
  if (!responderKeyRow) {
    // @rule:NLS-YK-001 unknown signer → REJECT
    const result = {
      decision: "attestation_unverifiable" as const,
      error: `Responder '${req.responder_id}' not in key registry — NLS-YK-001`,
      policy_hash: ph,
      latency_ms: Math.round(performance.now() - t0),
      rule_ref: "NLS-013/NLS-YK-001",
    };
    emitHandshakeSense("nallasetu.handshake.attestation_unverifiable", {
      initiator_id: req.initiator.agent_id, responder_id: req.responder_id,
      decision: result.decision, policy_hash: ph,
      latency_ms: result.latency_ms, rule_ref: result.rule_ref,
      error: result.error,
    });
    return result;
  }

  // @rule:NLS-YK-008 known-revoked partner → REJECT immediately
  if ((responderKeyRow as any).revoked === 1 || (responderKeyRow as any).revoked === true) {
    const result = {
      decision: "attestation_unverifiable" as const,
      error: `Responder '${req.responder_id}' is revoked — NLS-YK-008`,
      policy_hash: ph,
      latency_ms: Math.round(performance.now() - t0),
      rule_ref: "NLS-YK-008",
    };
    emitHandshakeSense("nallasetu.handshake.session_failed", {
      initiator_id: req.initiator.agent_id, responder_id: req.responder_id,
      decision: result.decision, policy_hash: ph,
      latency_ms: result.latency_ms, rule_ref: result.rule_ref,
    });
    return result;
  }

  // @rule:NLS-YK-005 clock skew — max 5 minutes tolerance on attestation issued_at
  const CLOCK_SKEW_MS = 5 * 60 * 1000;
  if (req.initiator.issued_at) {
    const initiatorIssuedAt = new Date(req.initiator.issued_at).getTime();
    const skewMs = Math.abs(Date.now() - initiatorIssuedAt);
    if (skewMs > CLOCK_SKEW_MS) {
      const result = {
        decision: "attestation_unverifiable" as const,
        error: `Clock skew ${Math.round(skewMs / 1000)}s exceeds 300s limit — NLS-YK-005`,
        policy_hash: ph,
        latency_ms: Math.round(performance.now() - t0),
        rule_ref: "NLS-YK-005",
      };
      emitHandshakeSense("nallasetu.handshake.attestation_unverifiable", {
        initiator_id: req.initiator.agent_id, responder_id: req.responder_id,
        decision: result.decision, reason: "clock_skew_exceeded", policy_hash: ph,
        latency_ms: result.latency_ms, rule_ref: result.rule_ref,
      });
      return result;
    }
  }

  // The responder is signed with ITS OWN private seal, held in the local keystore (Customer-Zero /
  // self-managed). A responder registered with a public key only (remote) cannot be signed here — it
  // must supply its own signed attestation. NLS-002.
  const responderPriv = loadPrivateKey(req.responder_id);
  if (!responderPriv) {
    const result = {
      decision: "attestation_unverifiable" as const,
      error: `No private key held locally for responder '${req.responder_id}' — it must supply its own signed attestation (NLS-002)`,
      policy_hash: ph, latency_ms: Math.round(performance.now() - t0), rule_ref: "NLS-002",
    };
    emitHandshakeSense("nallasetu.handshake.attestation_unverifiable", {
      initiator_id: req.initiator.agent_id, responder_id: req.responder_id,
      decision: result.decision, policy_hash: ph, latency_ms: result.latency_ms, rule_ref: result.rule_ref, error: result.error,
    });
    return result;
  }
  const responderOfferBase: Omit<AttestOffer, "signature"> = {
    agent_id: req.responder_id,
    trust_mask: responderKeyRow.trust_mask ?? 0xFFFF, // explicit registry value; default limited (not all-bits)
    mask_vocabulary: MASK_VOCABULARY,
    grade: "B",
    format: ATTESTATION_FORMAT,
    issued_at: now.toISOString(),
    expires_at: expiresAt,
    nonce: sessionNonce,
    public_key_id: responderKeyRow.public_key_id,
  };
  const responderOffer: AttestOffer = {
    ...responderOfferBase,
    signature: signAttest(responderOfferBase, responderPriv),
  };

  // Verify both attestations against the registry's PUBLIC keys — @rule:NLS-001 bilateral, NLS-002
  // asymmetric. A row with no public_key (legacy HMAC-era) verifies false: there is no secret fallback.
  const initiatorPub = lookupKey(req.initiator.agent_id)?.public_key ?? "";
  if (!verifyAttest(initiatorOffer, initiatorPub)) {
    const result = {
      decision: "attestation_unverifiable" as const,
      error: "Initiator attestation signature invalid",
      policy_hash: ph,
      latency_ms: Math.round(performance.now() - t0),
      rule_ref: "NLS-002",
    };
    emitHandshakeSense("nallasetu.handshake.attestation_unverifiable", {
      initiator_id: req.initiator.agent_id, responder_id: req.responder_id,
      decision: result.decision, policy_hash: ph,
      latency_ms: result.latency_ms, rule_ref: result.rule_ref,
      error: result.error,
    });
    return result;
  }
  if (!verifyAttest(responderOffer, responderKeyRow.public_key ?? "")) {
    const result = {
      decision: "attestation_unverifiable" as const,
      error: "Responder attestation signature invalid",
      policy_hash: ph,
      latency_ms: Math.round(performance.now() - t0),
      rule_ref: "NLS-002",
    };
    emitHandshakeSense("nallasetu.handshake.attestation_unverifiable", {
      initiator_id: req.initiator.agent_id, responder_id: req.responder_id,
      decision: result.decision, policy_hash: ph,
      latency_ms: result.latency_ms, rule_ref: result.rule_ref,
      error: result.error,
    });
    return result;
  }

  // ── Primitive 3: INTERSECT_PROPOSE ───────────────────────────────────────
  // @rule:NLS-003 — an AND is an intersection only if bit i means the same on both sides. Refuse to
  // intersect masks written in different vocabularies; the bits would not line up.
  if (initiatorOffer.mask_vocabulary !== responderOffer.mask_vocabulary) {
    const result = {
      decision: "attestation_unverifiable" as const,
      error: `Mask vocabulary mismatch: initiator='${initiatorOffer.mask_vocabulary}' responder='${responderOffer.mask_vocabulary}' — cannot intersect bitmasks across dialects (NLS-003)`,
      policy_hash: ph, latency_ms: Math.round(performance.now() - t0), rule_ref: "NLS-003",
    };
    emitHandshakeSense("nallasetu.handshake.attestation_unverifiable", {
      initiator_id: req.initiator.agent_id, responder_id: req.responder_id,
      decision: result.decision, policy_hash: ph, latency_ms: result.latency_ms, rule_ref: result.rule_ref, error: result.error,
    });
    return result;
  }
  // @rule:NLS-003 session_mask = A.mask AND B.mask AND scope.mask — never union
  const sessionMask = initiatorOffer.trust_mask & responderOffer.trust_mask & req.scope_mask;

  if (sessionMask === 0) {
    // @rule:NLS-YK-002 zero-intersection → graceful fail with diagnostic
    const result = {
      decision: "no_common_capability" as const,
      error: `Zero intersection: initiator=0x${initiatorOffer.trust_mask.toString(16)} responder=0x${responderOffer.trust_mask.toString(16)} scope=0x${req.scope_mask.toString(16)}`,
      policy_hash: ph,
      latency_ms: Math.round(performance.now() - t0),
      rule_ref: "NLS-YK-002",
    };
    emitHandshakeSense("nallasetu.handshake.no_common_capability", {
      initiator_id: req.initiator.agent_id, responder_id: req.responder_id,
      decision: result.decision, policy_hash: ph,
      latency_ms: result.latency_ms, rule_ref: result.rule_ref,
      error: result.error,
    });
    return result;
  }

  // Scope overreach check — @rule:NLS-YK-003
  const requestedBeyondInitiator = req.scope_mask & ~initiatorOffer.trust_mask;
  if (requestedBeyondInitiator !== 0) {
    const counterScope = req.scope_mask & initiatorOffer.trust_mask & responderOffer.trust_mask;
    const result = {
      decision: "scope_counter_proposed" as const,
      counter_scope_mask: counterScope,
      error: `Scope overreach on bits 0x${requestedBeyondInitiator.toString(16)} — counter-scope proposed`,
      policy_hash: ph,
      latency_ms: Math.round(performance.now() - t0),
      rule_ref: "NLS-YK-003",
    };
    emitHandshakeSense("nallasetu.handshake.scope_counter_proposed", {
      initiator_id: req.initiator.agent_id, responder_id: req.responder_id,
      decision: result.decision, counter_scope_mask: counterScope,
      policy_hash: ph, latency_ms: result.latency_ms, rule_ref: result.rule_ref,
      error: result.error,
    });
    return result;
  }

  const intersect: IntersectPropose = {
    initiator_mask: initiatorOffer.trust_mask,
    responder_mask: responderOffer.trust_mask,
    scope_mask: req.scope_mask,
    session_mask: sessionMask,
    proposed_ttl_seconds: ttlSeconds,
    session_class: sessionClass,
  };

  // ── Primitive 4: SESSION_CREDENTIAL ──────────────────────────────────────
  // @rule:NLS-006 mandatory TTL — @rule:NLS-008 no credential reuse
  const sessionId = generateSessionId();
  const credentialHash = hashCredential({
    session_id: sessionId,
    initiator_id: req.initiator.agent_id,
    responder_id: req.responder_id,
    session_mask: sessionMask,
    issued_at: now.toISOString(),
    expires_at: expiresAt,
  });

  const credential: SessionCredential = {
    session_id: sessionId,
    initiator_id: req.initiator.agent_id,
    responder_id: req.responder_id,
    session_mask: sessionMask,
    session_class: sessionClass,
    issued_at: now.toISOString(),
    expires_at: expiresAt,
    credential_hash: credentialHash,
    witness_nonce: generateNonce(),
  };

  // ── Primitive 5: SESSION_RECEIPT — PRAMANA-witnessed ─────────────────────
  // @rule:NLS-010 PRAMANA-witnessed — @rule:NLS-012 mandatory SENSE events
  // @rule:NLS-YK-006 witness unavailable → fail session retroactively
  const receiptHash = hashReceipt(credentialHash, "completed");
  let pramanaHash: string;
  try {
    const previousPramana = getLastPramanaHash();
    pramanaHash = pramanaWitness(receiptHash, previousPramana);
  } catch {
    const result = {
      decision: "handshake_timeout" as const,
      error: "PRAMANA witness unavailable — session failed retroactively (NLS-YK-006)",
      policy_hash: ph,
      latency_ms: Math.round(performance.now() - t0),
      rule_ref: "NLS-YK-006",
    };
    emitHandshakeSense("nallasetu.handshake.session_failed", {
      initiator_id: req.initiator.agent_id, responder_id: req.responder_id,
      decision: result.decision, reason: "witness_unavailable", policy_hash: ph,
      latency_ms: result.latency_ms, rule_ref: result.rule_ref,
    });
    return result;
  }

  const receipt: SessionReceipt = {
    session_id: sessionId,
    initiator_id: req.initiator.agent_id,
    responder_id: req.responder_id,
    session_mask: sessionMask,
    outcome: "completed",
    receipt_hash: receiptHash,
    pramana_witness: pramanaHash,
    issued_at: now.toISOString(),
    rule_ref: "NLS-010",
  };

  // Persist session and PRAMANA chain — @rule:NLS-011 append-only
  storeSession({
    session_id: sessionId,
    initiator_id: req.initiator.agent_id,
    responder_id: req.responder_id,
    session_mask: sessionMask,
    session_class: sessionClass,
    credential_json: JSON.stringify(credential),
    receipt_json: JSON.stringify(receipt),
    status: "active",
    issued_at: now.toISOString(),
    expires_at: expiresAt,
    pramana_hash: pramanaHash,
  });
  appendPramanaChain(sessionId, receiptHash, pramanaHash);

  const latency_ms = Math.round(performance.now() - t0);
  // @rule:NLS-012 SENSE event on every successful handshake
  emitHandshakeSense("nallasetu.handshake.session_issued", {
    session_id: sessionId,
    initiator_id: req.initiator.agent_id,
    responder_id: req.responder_id,
    session_mask: sessionMask,
    session_class: sessionClass,
    decision: "session_issued",
    policy_hash: ph,
    latency_ms,
    rule_ref: "NLS-001/NLS-003/NLS-010",
  }, sessionId);

  return {
    decision: "session_issued",
    session: credential,
    receipt,
    intersect,
    policy_hash: ph,
    latency_ms,
    rule_ref: "NLS-001/NLS-003/NLS-010",
  };
}
