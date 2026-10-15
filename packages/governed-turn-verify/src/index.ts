// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// @xshieldai/governed-turn-verify — the verifier of the Governed Turn Protocol (GTP), one function for
// every position a turn can be checked in (GTP-013, INF-GTP-010).
//
//   verifyTurn(envelope, context)   steps 5–9: capability, authority, intent, reversibility, commit.
//                                   Pure: no I/O, no model, no clock. Same inputs, same verdict.
//   checkTurn(turn, substrate)      steps 0–9 for one envelope, whatever carried it: an HTTP request's
//                                   headers, or the same fields carried as JSON to a hook (GTP-023).
//
// There is no "approved" input anywhere. A turn is exactly as powerful as its masks say (GTP-INV-6).
// Extracted from the GTP reference gate (gtp-gate), whose tests it carries.

import { createPrivateKey, createPublicKey, randomUUID, sign as edSign, verify as edVerify } from "node:crypto";

// ── types ─────────────────────────────────────────────────────────────────────────────────────────

export type Verb = "can_read" | "can_act" | "can_model";
export type Reversibility = "reversible" | "compensable" | "irreversible";
export type Level = "L0" | "L1" | "L2" | "L3" | "L4";
export type Mask = number | bigint;

export interface Driver { type: "human" | "agent" | string; id: string; keyid?: string }
export interface Capability { service?: string; slug: string; verb: Verb | string; bit: number }

export interface TurnEnvelope {
  driver?: Driver;
  capability?: Capability | null;
  commit?: "auto" | "pause" | string;
  reversibilityClaim?: string;
  authority?: { declaredBudgetLeft?: number };
  intent?: { present: boolean; digest?: string; verdict?: string };
}

export interface CatalogEntry { bit: number; verb: string; reversibility?: string }
export type Catalog = Record<string, CatalogEntry>;

export interface VerifyContext {
  sessionMask?: Mask;
  driverTrustMask?: Mask;
  catalog?: Catalog;
  sealedBudgetLeft?: number;
  parentMask?: Mask | null;
  intentVerdict?: "pass" | "fail" | string;
  level?: Level;
}

export interface Verdict {
  ok: boolean;
  status: "PASS" | "PAUSED" | "REFUSED";
  httpCode: number;
  code: string;
  rule: string;
  detail: string;
  [extra: string]: unknown;
}

// ── steps 5–9: the decision ───────────────────────────────────────────────────────────────────────

/** Bitwise membership. @rule:GTP-006 */
const bitSet = (mask: Mask | undefined | null, bit: number): boolean => (BigInt(mask ?? 0) & (1n << BigInt(bit))) !== 0n;
/** Does `sub` hold a bit `sup` lacks? @rule:GTP-INV-2 */
const exceeds = (sub: Mask | undefined | null, sup: Mask | undefined | null): boolean => (BigInt(sub ?? 0) & ~BigInt(sup ?? 0)) !== 0n;

const REVERSIBILITY = new Set(["reversible", "compensable", "irreversible"]);
const VERBS = new Set(["can_read", "can_act", "can_model"]);

function refuse(httpCode: number, code: string, rule: string, detail: string, extra: Record<string, unknown> = {}): Verdict {
  return { ok: false, status: "REFUSED", httpCode, code, rule, detail, ...extra };
}

/**
 * Decide one governed turn, given the results of steps 0–4 as inputs. The envelope is what the driver
 * presents (already signature-checked); the context is substrate truth the caller injects (the verifier
 * never fetches). `level` is reported only: the verdict is always the honest decision.
 */
export function verifyTurn(envelope: TurnEnvelope = {}, context: VerifyContext = {}): Verdict {
  const { driver, capability: cap, commit = "auto", reversibilityClaim, authority = {}, intent } = envelope;
  const { sessionMask, driverTrustMask, catalog = {}, sealedBudgetLeft = Infinity, parentMask = null, intentVerdict, level = "L4" } = context;

  if (!driver || !driver.type) return refuse(400, "GTP_ENVELOPE_MALFORMED", "GTP-004", "missing driver");
  if (!cap || !cap.slug || typeof cap.bit !== "number" || !Number.isInteger(cap.bit) || cap.bit < 0)
    return refuse(400, "GTP_ENVELOPE_MALFORMED", "GTP-004", "missing capability slug/bit");
  if (!VERBS.has(cap.verb)) return refuse(400, "GTP_ENVELOPE_MALFORMED", "GTP-004", `unknown verb ${cap.verb}`);

  // step 5: capability, by mask intersection only  @rule:GTP-006
  const entry = Object.prototype.hasOwnProperty.call(catalog, cap.slug) ? catalog[cap.slug] : undefined;
  if (!entry) return refuse(403, "GTP_CAPABILITY_DENIED", "GTP-006", `slug not in catalog: ${cap.slug}`, { slug: cap.slug });
  if (entry.bit !== cap.bit)
    return refuse(403, "GTP_CAPABILITY_DENIED", "GTP-006", `claimed bit ${cap.bit} ≠ catalog bit ${entry.bit} for ${cap.slug}`, { slug: cap.slug, claimedBit: cap.bit, catalogBit: entry.bit });
  if (entry.verb !== cap.verb)
    return refuse(403, "GTP_CAPABILITY_DENIED", "GTP-006", `verb ${cap.verb} ≠ catalog verb ${entry.verb} for ${cap.slug}`, { slug: cap.slug });
  if (!bitSet(sessionMask, cap.bit))
    return refuse(403, "GTP_CAPABILITY_DENIED", "GTP-006", `session_mask bit ${cap.bit} unset — capability not in this session's ceiling`, { slug: cap.slug, bit: cap.bit });
  // a driver cannot exercise a capability its own trust_mask lacks  @rule:GTP-INV-6
  if (!bitSet(driverTrustMask, cap.bit))
    return refuse(403, "GTP_CAPABILITY_DENIED", "GTP-INV-6", `driver ${driver.type}:${driver.id} trust_mask lacks bit ${cap.bit} — a driver cannot self-authorize a capability it does not hold`, { slug: cap.slug, bit: cap.bit, driver: driver.type });

  // step 6: authority: attenuation and budget
  if (parentMask !== null && parentMask !== undefined && exceeds(driverTrustMask, parentMask))
    return refuse(403, "GTP_CAPABILITY_DENIED", "GTP-INV-2", "driver mask exceeds parent — spawn invariant violated (child ⊄ parent)", { driver: driver.id });
  if (sealedBudgetLeft <= 0)
    return refuse(402, "GTP_BUDGET_EXHAUSTED", "GTP-INV-1", "sealed budget ceiling reached", { sealedBudgetLeft });
  if (authority.declaredBudgetLeft != null && authority.declaredBudgetLeft > sealedBudgetLeft)
    return refuse(403, "GTP_AUTHORITY_LIE", "GTP-010", `declared budget ${authority.declaredBudgetLeft} exceeds sealed ${sealedBudgetLeft} — lying envelope`, { sealedBudgetLeft });

  // step 7: intent, required for writes
  if (cap.verb === "can_act" && !(intent && intent.present))
    return refuse(403, "GTP_INTENT_MISSING", "GTP-005", "can_act turn requires a declared intent", { slug: cap.slug });
  if (intentVerdict === "fail")
    return refuse(403, "GTP_INTENT_REFUSED", "GTP-005", "intent guard refused this turn", { slug: cap.slug });

  // step 8: reversibility: the catalog is truth; no self-declared softening
  const reversibility = entry.reversibility;
  if (reversibility && !REVERSIBILITY.has(reversibility))
    return refuse(403, "GTP_ENVELOPE_MALFORMED", "GTP-004", `catalog reversibility invalid: ${reversibility}`);
  if (reversibilityClaim != null && reversibility != null && reversibilityClaim !== reversibility)
    return refuse(403, "GTP_REVERSIBILITY_MISMATCH", "GTP-009", `claimed '${reversibilityClaim}' ≠ catalog '${reversibility}' — cannot self-soften`, { slug: cap.slug });

  // step 9: commit: irreversible never auto-commits  @rule:GTP-009
  let effectiveCommit = commit;
  let forcedPause = false;
  if (cap.verb === "can_act" && reversibility === "irreversible" && commit === "auto") { effectiveCommit = "pause"; forcedPause = true; }
  if (cap.verb === "can_act" && effectiveCommit === "pause") {
    return {
      ok: true, status: "PAUSED", httpCode: 423, code: "GTP_PAUSED", rule: "GTP-007",
      detail: forcedPause ? `irreversible write held for approval (auto→pause forced; ${cap.slug})` : `write held awaiting approval (${cap.slug})`,
      approvalRequired: true, reversibility, effectiveCommit, level, slug: cap.slug,
    };
  }
  return {
    ok: true, status: "PASS", httpCode: 200, code: "GTP_PASS", rule: "GTP-006",
    detail: `${driver.type}:${driver.id} cleared ${cap.verb} ${cap.slug} (bit ${cap.bit})`,
    reversibility, effectiveCommit, level, slug: cap.slug,
  };
}

/** The wire refusal body (application/gtp-refusal+json). @rule:GTP-005 */
export function refusalBody(turnId: string, verdict: Verdict): Record<string, unknown> {
  return {
    gtp: "0.4", turn: turnId, code: verdict.code, rule: verdict.rule,
    detail: { message: verdict.detail, ...("slug" in verdict ? { slug: verdict.slug } : {}), ...("bit" in verdict ? { bit: verdict.bit } : {}) },
    recoverable: verdict.httpCode === 403 || verdict.httpCode === 402,
    recovery: verdict.httpCode === 423
      ? "await human approval (a new governed turn by a human driver)"
      : "re-handshake (Nallasetu) with narrower scope or an escalated principal",
  };
}

// ── the envelope: GTP-* fields, signed with Ed25519 ──────────────────────────────────────────────
// Simplified RFC 9421 profile: covered components are newline-joined "name: value" lines in a fixed
// order, plus @method, @path, @created, @nonce and @keyid. Same base as the reference gate.

/** The covered GTP fields, in canonical order. @rule:GTP-004 */
export const GTP_FIELDS = [
  "gtp-version", "gtp-turn", "gtp-driver", "gtp-principal", "gtp-session",
  "gtp-capability", "gtp-authority", "gtp-intent", "gtp-reversibility", "gtp-commit",
] as const;

export type Fields = Record<string, string | undefined>;

/** Parse a structured-field dictionary `k=v; k="v"` into an object (quotes stripped). */
export function parseDict(s: string | undefined | null): Record<string, string> {
  const o: Record<string, string> = {};
  if (!s) return o;
  for (const part of String(s).split(";")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    const k = part.slice(0, i).trim();
    let v = part.slice(i + 1).trim();
    if (v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1);
    o[k] = v;
  }
  return o;
}

/** Is a GTP envelope present? (step 0, classify) */
export function hasEnvelope(fields: Fields): boolean {
  return GTP_FIELDS.some((f) => fields[f] != null);
}

/** The signature base string for a method, path, fields and binding parameters. */
export function signatureBase(method: string, path: string, fields: Fields, { created, nonce, keyid }: { created: number | string; nonce: string; keyid: string }): string {
  const lines = [`@method: ${String(method).toUpperCase()}`, `@path: ${path}`];
  for (const f of GTP_FIELDS) if (fields[f] != null) lines.push(`${f}: ${fields[f]}`);
  lines.push(`@created: ${created}`, `@nonce: ${nonce}`, `@keyid: ${keyid}`);
  return lines.join("\n");
}

/**
 * Sign an envelope: returns the fields with `signature-input` and `signature` added. `created` defaults to
 * now (seconds) and `nonce` to a random UUID: a checker accepts `created` only within its window (300 s by
 * default, GTP-YK-003) and a nonce only once, so a fixed value works once at most.
 */
export function signEnvelope(a: { method: string; path: string; headers: Fields; privateKeyPem: string; keyid: string; created?: number; nonce?: string }): Fields {
  const created = a.created ?? Math.floor(Date.now() / 1000);
  const nonce = a.nonce ?? randomUUID();
  const base = signatureBase(a.method, a.path, a.headers, { created, nonce, keyid: a.keyid });
  const sig = edSign(null, Buffer.from(base), createPrivateKey(a.privateKeyPem)).toString("base64");
  return { ...a.headers, "signature-input": `created=${created}; nonce="${nonce}"; keyid="${a.keyid}"`, signature: sig };
}

/** Check the signature against a public key. @rule:GTP-011 */
export function verifySignature(a: { method: string; path: string; headers: Fields; publicKeyPem: string }): { ok: boolean; reason?: string; keyid?: string; created?: number; nonce?: string } {
  const si = parseDict(a.headers["signature-input"]);
  if (!si.keyid || !si.created || !si.nonce) return { ok: false, reason: "malformed signature-input" };
  if (!a.headers.signature) return { ok: false, reason: "no signature" };
  const base = signatureBase(a.method, a.path, a.headers, { created: si.created, nonce: si.nonce, keyid: si.keyid });
  let ok = false;
  try { ok = edVerify(null, Buffer.from(base), createPublicKey(a.publicKeyPem), Buffer.from(a.headers.signature, "base64")); } catch { ok = false; }
  return { ok, keyid: si.keyid, created: Number(si.created), nonce: si.nonce };
}

export interface ParsedEnvelope extends TurnEnvelope {
  driver: Driver;
  capability: Capability | null;
  commit: string;
  authority: { declaredBudgetLeft?: number };
  turn: { id?: string; chain?: string; parent?: string };
  principal: { sub?: string; depth?: number };
  sessionCred?: string;
  seal?: string;
}

/** Parse the envelope's fields into the shapes verifyTurn takes. */
export function parseEnvelope(fields: Fields): ParsedEnvelope {
  const driver = parseDict(fields["gtp-driver"]);
  const capRaw = parseDict(fields["gtp-capability"]);
  const session = parseDict(fields["gtp-session"]);
  const authority = parseDict(fields["gtp-authority"]);
  const intentRaw = parseDict(fields["gtp-intent"]);
  const turn = parseDict(fields["gtp-turn"]);
  const principal = parseDict(fields["gtp-principal"]);
  const commit = parseDict(fields["gtp-commit"]).mode || "auto";
  const reversibilityClaim = parseDict(fields["gtp-reversibility"]).class || undefined;
  return {
    driver: { type: driver.type, id: driver.id, keyid: driver.keyid },
    capability: capRaw.slug ? { service: capRaw.service, slug: capRaw.slug, verb: capRaw.verb, bit: Number(capRaw.bit) } : null,
    commit, reversibilityClaim,
    authority: authority["budget-left"] != null ? { declaredBudgetLeft: Number(authority["budget-left"]) } : {},
    intent: intentRaw.present != null ? { present: intentRaw.present === "true", digest: intentRaw.digest, verdict: intentRaw.verdict } : undefined,
    turn: { id: turn.id, chain: turn.chain, parent: turn.parent },
    principal: { sub: principal.sub, depth: principal.depth != null ? Number(principal.depth) : undefined },
    sessionCred: session.cred, seal: session.seal,
  };
}

// ── the local binding (GTP-023): the same envelope, carried as JSON ──────────────────────────────

/** One envelope, whatever carried it: the request line it was signed for, and its fields. */
export interface LocalEnvelope { method: string; path: string; fields: Fields }

/** The envelope inside an HTTP request: the GTP fields and the two signature fields, nothing else. */
export function envelopeFromHeaders(method: string, path: string, headers: Record<string, string | string[] | undefined>): LocalEnvelope {
  const fields: Fields = {};
  for (const name of [...GTP_FIELDS, "signature-input", "signature"]) {
    const v = headers[name];
    if (v != null) fields[name] = Array.isArray(v) ? v.join(", ") : v;
  }
  return { method: String(method).toUpperCase(), path, fields };
}

/** An envelope carried as JSON (a hook payload, an environment variable, a file). Refuses anything else. */
export function envelopeFromJson(value: unknown): LocalEnvelope | null {
  if (!value || typeof value !== "object") return null;
  const v = value as Record<string, unknown>;
  if (typeof v.method !== "string" || typeof v.path !== "string" || !v.fields || typeof v.fields !== "object" || Array.isArray(v.fields)) return null;
  const fields: Fields = {};
  for (const [k, x] of Object.entries(v.fields as Record<string, unknown>)) if (typeof x === "string") fields[k.toLowerCase()] = x;
  return { method: v.method.toUpperCase(), path: v.path, fields };
}

// ── steps 0–9 for one envelope ────────────────────────────────────────────────────────────────────

/** A registered key. It speaks for exactly one driver. */
export interface KeyEntry { publicKey: string; driverId: string; driverType: string }

export interface Session {
  sessionMask: Mask;
  trustByDriver?: Record<string, Mask>;
  sealedBudgetLeft?: number;
  parentMask?: Mask | null;
  [extra: string]: unknown;
}

export interface Substrate {
  keyRegistry: Record<string, KeyEntry>;
  /** The session for a credential: a map, or a lookup that may be async. Null or undefined = no such session. */
  sessions: Record<string, Session> | ((cred: string) => Session | null | undefined | Promise<Session | null | undefined>);
  catalog: Catalog;
  level?: Level;
  /** Nonces already seen and when they stop mattering (ms). Give the same map to every call of one checker. */
  seenNonces?: Map<string, number>;
  /** How far `created` may be from now, either way (ms). Default 300 000 (GTP-YK-003). */
  windowMs?: number;
  /** The time to judge at (ms). Default Date.now(). */
  now?: number;
}

export interface CheckResult {
  verdict: Verdict;
  turnId: string;
  /** Whether a refusal at this level stops the turn. L0 never does; the verdict is the same either way. */
  enforced: boolean;
  driver?: string;
  slug?: string;
}

const identityRefusal = (detail: string): Verdict => ({ ok: false, status: "REFUSED", httpCode: 401, code: "GTP_UNIDENTIFIED", rule: "GTP-011", detail });

/**
 * Check one envelope end to end. The same call serves an HTTP gate (envelopeFromHeaders) and a hook or
 * other local position (envelopeFromJson), so a turn is judged the same at every hop (INF-GTP-010).
 */
export async function checkTurn(env: LocalEnvelope, sub: Substrate): Promise<CheckResult> {
  const level: Level = sub.level ?? "L1";
  const enforced = level !== "L0";
  const now = sub.now ?? Date.now();
  const windowMs = sub.windowMs ?? 300_000;
  const done = (verdict: Verdict, turnId: string, extra: Partial<CheckResult> = {}): CheckResult => ({ verdict, turnId, enforced, ...extra });

  // step 0: classify  @rule:GTP-INV-3
  if (!hasEnvelope(env.fields))
    return done({ ok: false, status: "REFUSED", httpCode: 428, code: "GTP_ENVELOPE_REQUIRED", rule: "GTP-INV-3", detail: "agent-originated traffic needs a GTP envelope at this gate level" }, "");

  // step 1: parse  @rule:GTP-004
  let p: ParsedEnvelope;
  try { p = parseEnvelope(env.fields); } catch { return done({ ok: false, status: "REFUSED", httpCode: 400, code: "GTP_ENVELOPE_MALFORMED", rule: "GTP-004", detail: "envelope could not be parsed" }, ""); }
  const turnId = p.turn.id || "";
  const who = { driver: p.driver.id };

  // step 2: signature, freshness, replay  @rule:GTP-011 @rule:GTP-YK-003
  const key = p.driver.keyid ? sub.keyRegistry[p.driver.keyid] : undefined;
  if (!key || !Object.prototype.hasOwnProperty.call(sub.keyRegistry, p.driver.keyid!)) return done(identityRefusal(`unknown keyid ${p.driver.keyid}`), turnId, who);
  const sig = verifySignature({ method: env.method, path: env.path, headers: env.fields, publicKeyPem: key.publicKey });
  if (!sig.ok) return done(identityRefusal(sig.reason ?? "bad signature"), turnId, who);
  if (sig.keyid !== p.driver.keyid) return done(identityRefusal(`signed with ${sig.keyid}, envelope names ${p.driver.keyid}`), turnId, who);
  // step 3: a key speaks only for the driver it is registered to (a key registered to none identifies nobody)
  if (key.driverId !== p.driver.id || key.driverType !== p.driver.type)
    return done(identityRefusal(`key ${p.driver.keyid} is registered to ${key.driverType}:${key.driverId}, not ${p.driver.type}:${p.driver.id}`), turnId, who);
  const createdMs = (sig.created ?? NaN) * 1000;
  if (!Number.isFinite(createdMs) || Math.abs(now - createdMs) > windowMs)
    return done(identityRefusal(`created ${sig.created} is outside the ${windowMs / 1000}s window`), turnId, who);
  if (sub.seenNonces) {
    for (const [n, until] of sub.seenNonces) if (until < now) sub.seenNonces.delete(n);
    if (sub.seenNonces.has(sig.nonce!)) return done(identityRefusal("replayed nonce"), turnId, who);
    sub.seenNonces.set(sig.nonce!, createdMs + windowMs);
  }

  // step 4: session
  const sess = !p.sessionCred ? null
    : typeof sub.sessions === "function" ? await sub.sessions(p.sessionCred)
    : Object.prototype.hasOwnProperty.call(sub.sessions, p.sessionCred) ? sub.sessions[p.sessionCred] : null;
  if (!sess) return done(identityRefusal("dead or unknown session"), turnId, who);

  // steps 5–9
  const verdict = verifyTurn(
    { driver: p.driver, capability: p.capability, commit: p.commit, reversibilityClaim: p.reversibilityClaim, authority: p.authority, intent: p.intent },
    { sessionMask: sess.sessionMask, driverTrustMask: sess.trustByDriver?.[p.driver.id] ?? 0, catalog: sub.catalog, sealedBudgetLeft: sess.sealedBudgetLeft, parentMask: sess.parentMask ?? null, intentVerdict: p.intent?.verdict, level },
  );
  return done(verdict, turnId, { ...who, slug: p.capability?.slug });
}

export default verifyTurn;
