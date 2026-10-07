// @xshieldai/aegis-guard — v0.4.0 hardening tests
//
// What these pin:
//   §H1 key      (AEG-HG-2B-007) a box that was given a key to trust never makes its own;
//                a box whose keys disagree trusts none
//   §H2 token    (AEG-HG-2B-008) every field a decision rests on is type-checked; a refusal
//                is always IrrNoApprovalError
//   §H3 nonce    (AEG-HG-2B-006/008)
//   §H4 duplicate (AEG-HG-2B-009) and the fingerprint
//   §H5 audit event (AEG-HG-2B-005)
//   §H6 quality bar (AEG-Q-003)
//   §H7 envelope (ASE-016), fetch stubbed
//   §H8 limits   what the package does not do, so a change in any of them is noticed
//
// Hermetic: every key lives in a temp directory; no network.

import { describe, it, expect, beforeEach, afterEach } from 'bun:test';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, statSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { generateKeyPairSync, sign as edSign, createPrivateKey } from 'crypto';

const ROOT = mkdtempSync(join(tmpdir(), 'aegis-guard-hardening-'));
const dir = (n: string) => mkdtempSync(join(ROOT, n + '-'));
const AUTH = dir('authority');
const SAVED_DIR = process.env.AEGIS_DIR;
const SAVED_PEM = process.env.AEGIS_APPROVAL_PUBKEY_PEM;

import {
  IrrNoApprovalError,
  ensureSigningKeypair,
  getPublicKeyPem,
  signApprovalJwt,
  verifyApprovalJwt,
  mintApprovalToken,
  verifyApprovalToken,
  verifyScopedApprovalToken,
  verifyAndConsumeNonce,
  digestApprovalToken,
  checkIdempotency,
  buildIdempotencyFingerprint,
  emitAegisSenseEvent,
  configureSenseTransport,
  setEventBus,
  buildQualityMaskAtPromotion,
  buildQualityDriftScore,
  meetsHgQualityRequirement,
  HG_REQUIRED_MASKS,
  issueEnvelope,
  verifyEnvelope,
  type AccReceipt,
  type NonceStore,
} from '../src/index.js';

// Each call names its box: the directory, and optionally the key given by environment.
function on<T>(boxDir: string, fn: () => T, envPem?: string): T {
  process.env.AEGIS_DIR = boxDir;
  if (envPem === undefined) delete process.env.AEGIS_APPROVAL_PUBKEY_PEM;
  else process.env.AEGIS_APPROVAL_PUBKEY_PEM = envPem;
  try { return fn(); } finally { process.env.AEGIS_DIR = AUTH; delete process.env.AEGIS_APPROVAL_PUBKEY_PEM; }
}

// v0.6.0: minting/key-generation is an authority action; this suite is the authority.
process.env.AEGIS_MINT_AUTHORITY = '1';
const AUTH_PUB = on(AUTH, () => ensureSigningKeypair().publicKeyPem);
const AUTH_KEY = readFileSync(join(AUTH, 'approval-signing.key'), 'utf8');
const other = generateKeyPairSync('ed25519');
const OTHER_PUB = other.publicKey.export({ type: 'spki', format: 'pem' }).toString();

const box = (files: { key?: string; pub?: string } = {}) => {
  const d = dir('box');
  if (files.key) writeFileSync(join(d, 'approval-signing.key'), files.key, { mode: 0o600 });
  if (files.pub) writeFileSync(join(d, 'approval-signing.pub'), files.pub);
  return d;
};
const base = (over: Record<string, unknown> = {}) => ({
  service_id: 'svc', capability: 'settle', operation: 'record_settle',
  issued_at: Date.now() - 1000, expires_at: Date.now() + 60_000,
  nonce: 'n-' + Math.random().toString(36).slice(2), ...over,
});
const without = (o: Record<string, unknown>, k: string) => { const c = { ...o }; delete c[k]; return c; };
const sign = (payload: unknown) => on(AUTH, () => signApprovalJwt(payload as any));
const b64 = (s: string) => Buffer.from(s).toString('base64url');
const signedBy = (key: any, payload: unknown, header = '{"alg":"EdDSA","typ":"JWT"}') => {
  const h = b64(header); const b = b64(JSON.stringify(payload));
  return `${h}.${b}.${edSign(null, Buffer.from(`${h}.${b}`), key).toString('base64url')}`;
};
const verify = (token: unknown, boxDir = AUTH, envPem?: string) =>
  on(boxDir, () => verifyApprovalToken(token as any, 'svc', 'settle', 'record_settle'), envPem);
const scoped = (token: unknown, scope: unknown) =>
  on(AUTH, () => verifyScopedApprovalToken(token as any, 'svc', 'settle', 'record_settle', scope as any));
const memStore = (): NonceStore => { const used = new Set<string>(); return { consumeNonce: async (n) => (used.has(n) ? false : (used.add(n), true)) }; };

beforeEach(() => { process.env.AEGIS_DIR = AUTH; delete process.env.AEGIS_APPROVAL_PUBKEY_PEM; setEventBus(null); configureSenseTransport(() => {}); });
afterEach(() => {
  if (SAVED_DIR === undefined) delete process.env.AEGIS_DIR; else process.env.AEGIS_DIR = SAVED_DIR;
  if (SAVED_PEM === undefined) delete process.env.AEGIS_APPROVAL_PUBKEY_PEM; else process.env.AEGIS_APPROVAL_PUBKEY_PEM = SAVED_PEM;
  setEventBus(null);
});

// ─── §H1 key ──────────────────────────────────────────────────────────────────

describe('§H1 which key a box trusts (AEG-HG-2B-007)', () => {
  it('GH-101: the authority mints and verifies', () => {
    expect(verify(on(AUTH, () => mintApprovalToken(base() as any))).service_id).toBe('svc');
  });

  it('GH-101b: minting is an authority action — a non-authority process is refused (review point 1, key leg)', () => {
    const saved = process.env.AEGIS_MINT_AUTHORITY;
    delete process.env.AEGIS_MINT_AUTHORITY; // an ordinary agent, not the authority
    try {
      // the signing key is present on this box, yet a non-authority process still cannot mint
      expect(() => on(AUTH, () => mintApprovalToken(base() as any))).toThrow(/authority/i);
      // the explicit opt-out (AEGIS_ALLOW_INSECURE_LOCAL_MINT) restores single-process minting
      process.env.AEGIS_ALLOW_INSECURE_LOCAL_MINT = '1';
      try { expect(typeof on(AUTH, () => mintApprovalToken(base() as any))).toBe('string'); }
      finally { delete process.env.AEGIS_ALLOW_INSECURE_LOCAL_MINT; }
    } finally {
      if (saved === undefined) delete process.env.AEGIS_MINT_AUTHORITY;
      else process.env.AEGIS_MINT_AUTHORITY = saved;
    }
  });

  it('GH-102: a box with the public file only verifies the authority\'s token', () => {
    expect(verify(sign(base()), box({ pub: AUTH_PUB })).capability).toBe('settle');
  });

  it('GH-103: a box given the key by environment only verifies it too', () => {
    expect(verify(sign(base()), box(), AUTH_PUB).capability).toBe('settle');
  });

  it('GH-104: minting on a box with no key throws and writes nothing', () => {
    const d = box();
    expect(() => on(d, () => mintApprovalToken(base() as any))).toThrow(/no AEGIS approval signing key/);
    expect(existsSync(join(d, 'approval-signing.key'))).toBe(false);
    expect(existsSync(join(d, 'approval-signing.pub'))).toBe(false);
  });

  it('GH-105: minting on a verifier box throws and leaves its public key file as it was', () => {
    const d = box({ pub: AUTH_PUB });
    expect(() => on(d, () => mintApprovalToken(base() as any))).toThrow();
    expect(readFileSync(join(d, 'approval-signing.pub'), 'utf8')).toBe(AUTH_PUB);
    expect(existsSync(join(d, 'approval-signing.key'))).toBe(false);
    expect(verify(sign(base()), d).service_id).toBe('svc');
  });

  it('GH-106: ensureSigningKeypair refuses on a verifier box, by file or by environment', () => {
    const d = box({ pub: AUTH_PUB });
    expect(() => on(d, () => ensureSigningKeypair())).toThrow(/AEG-HG-2B-007/);
    expect(readFileSync(join(d, 'approval-signing.pub'), 'utf8')).toBe(AUTH_PUB);
    const e = box();
    expect(() => on(e, () => ensureSigningKeypair(), AUTH_PUB)).toThrow(/AEG-HG-2B-007/);
    expect(existsSync(join(e, 'approval-signing.key'))).toBe(false);
  });

  it('GH-107: ensureSigningKeypair on an empty box makes one key, mode 600, and keeps it', () => {
    const d = box();
    const first = on(d, () => ensureSigningKeypair()).publicKeyPem;
    expect(statSync(join(d, 'approval-signing.key')).mode & 0o777).toBe(0o600);
    expect(on(d, () => ensureSigningKeypair()).publicKeyPem).toBe(first);
    expect(on(d, () => getPublicKeyPem())).toBe(first);
  });

  it('GH-108: a lost public file is re-derived from the private key, never regenerated', () => {
    const d = box({ key: AUTH_KEY });
    expect(on(d, () => ensureSigningKeypair()).publicKeyPem).toBe(AUTH_PUB);
  });

  it('GH-109: private key and public file disagree → nothing is trusted, nothing is minted', () => {
    const d = box({ key: AUTH_KEY, pub: OTHER_PUB });
    expect(() => verify(sign(base()), d)).toThrow(IrrNoApprovalError);
    expect(() => verify(signedBy(other.privateKey, base()), d)).toThrow(IrrNoApprovalError);
    expect(() => on(d, () => mintApprovalToken(base() as any))).toThrow();
    const token = sign(base()); // signed first: sign() switches box and back
    const r = on(d, () => verifyApprovalJwt(token));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain('AEG-HG-2B-007');
  });

  it('GH-110: file and environment disagree → nothing is trusted', () => {
    expect(() => verify(sign(base()), box({ pub: AUTH_PUB }), OTHER_PUB)).toThrow(IrrNoApprovalError);
    expect(() => verify(sign(base()), AUTH, OTHER_PUB)).toThrow(IrrNoApprovalError);
  });

  it('GH-111: file and environment agree → trusted', () => {
    expect(verify(sign(base()), box({ pub: AUTH_PUB }), AUTH_PUB).service_id).toBe('svc');
    expect(verify(sign(base()), AUTH, AUTH_PUB).service_id).toBe('svc');
  });

  it('GH-112: key material that is not a usable Ed25519 key → nothing is trusted', () => {
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ type: 'spki', format: 'pem' }).toString();
    expect(() => verify(sign(base()), box({ pub: 'garbage' }))).toThrow(IrrNoApprovalError);
    expect(() => verify(sign(base()), box({ pub: rsa }))).toThrow(IrrNoApprovalError);
    expect(() => verify(sign(base()), box({ pub: AUTH_PUB }), 'not a pem')).toThrow(IrrNoApprovalError);
    expect(() => verify(sign(base()), box({ key: 'garbage', pub: AUTH_PUB }))).toThrow(IrrNoApprovalError);
  });

  it('GH-113: a change of the environment key is picked up without a restart', () => {
    const d = box();
    const t = sign(base());
    expect(verify(t, d, AUTH_PUB).service_id).toBe('svc');
    expect(() => verify(t, d, OTHER_PUB)).toThrow(IrrNoApprovalError);
  });
});

// ─── §H2 token ────────────────────────────────────────────────────────────────

describe('§H2 the token is read strictly (AEG-HG-2B-008)', () => {
  const refusedTokens: [string, () => unknown][] = [
    ['no expiry', () => sign(without(base(), 'expires_at'))],
    ['expiry null', () => sign(base({ expires_at: null }))],
    ['expiry as text', () => sign(base({ expires_at: String(Date.now() + 60_000) }))],
    ['expiry "never"', () => sign(base({ expires_at: 'never' }))],
    ['expiry 0', () => sign(base({ expires_at: 0 }))],
    ['expiry true', () => sign(base({ expires_at: true }))],
    ['expiry as a list', () => sign(base({ expires_at: [Date.now() + 60_000] }))],
    // 1e400 is valid JSON and reads as Infinity
    ['expiry written as 1e400', () => { const h = b64('{"alg":"EdDSA","typ":"JWT"}'); const b = b64(JSON.stringify(base()).replace(/"expires_at":\d+/, '"expires_at":1e400')); return `${h}.${b}.${edSign(null, Buffer.from(`${h}.${b}`), createPrivateKey(AUTH_KEY)).toString('base64url')}`; }],
    ['issued_at as text', () => sign(base({ issued_at: 'yesterday' }))],
    ['issued_at null', () => sign(base({ issued_at: null }))],
    ['issued after it expires', () => sign(base({ issued_at: Date.now() + 50_000, expires_at: Date.now() + 40_000 }))],
    ['status denied', () => sign(base({ status: 'denied' }))],
    ['status revoked', () => sign(base({ status: 'revoked' }))],
    ['status REVOKED', () => sign(base({ status: 'REVOKED' }))],
    ['status pending', () => sign(base({ status: 'pending' }))],
    ['status Approved', () => sign(base({ status: 'Approved' }))],
    ['status null', () => sign(base({ status: null }))],
    ['status empty', () => sign(base({ status: '' }))],
    ['nonce an object', () => sign(base({ nonce: { id: 7 } }))],
    ['nonce a number', () => sign(base({ nonce: 7 }))],
    ['service_id a list', () => sign(base({ service_id: ['svc'] }))],
    ['body is null', () => sign(null)],
    ['body is a list', () => sign([base()])],
    ['token undefined', () => undefined],
    ['token null', () => null],
    ['token a number', () => 42],
    ['token an object', () => ({ service_id: 'svc' })],
    ['token empty', () => ''],
    ['signature with "!!" added', () => sign(base()) + '!!'],
    ['signature with "=" added', () => sign(base()) + '='],
    ['signature one character short', () => sign(base()).slice(0, -1)],
    ['a newline after the token', () => sign(base()) + '\n'],
    ['header alg as a list', () => signedBy(createPrivateKey(AUTH_KEY), base(), '{"alg":["EdDSA"]}')],
    ['header null', () => signedBy(createPrivateKey(AUTH_KEY), base(), 'null')],
  ];
  for (const [name, make] of refusedTokens) {
    it(`GH-2xx refused with the package's own error: ${name}`, () => {
      let err: unknown;
      try { verify(make()); } catch (e) { err = e; }
      expect(err).toBeInstanceOf(IrrNoApprovalError);
    });
  }

  it('GH-250: genuine tokens the strict reading must not turn away', () => {
    expect(verify(sign(without(without(base(), 'issued_at'), 'nonce'))).service_id).toBe('svc');
    expect(verify(sign(base({ status: 'approved' }))).status).toBe('approved');
    expect(verify(sign(base({ issued_at: Date.now() + 30_000 }))).service_id).toBe('svc');
    expect(verify(sign(base({ expires_at: Date.now() + 60_000.5, issued_by: 'ops', extra: { a: 1 } }))).issued_by).toBe('ops');
  });

  it('GH-251: the expected scope must be non-empty text', () => {
    const t = sign(without(base(), 'service_id'));
    expect(() => on(AUTH, () => verifyApprovalToken(t, undefined as any, 'settle', 'record_settle'))).toThrow(IrrNoApprovalError);
    const e = sign(base({ service_id: '', capability: '', operation: '' }));
    expect(() => on(AUTH, () => verifyApprovalToken(e, '', '', ''))).toThrow(IrrNoApprovalError);
  });

  it('GH-252: scoped — a field with no value binds nothing and is refused', () => {
    expect(() => scoped(sign(base()), { vessel_id: undefined })).toThrow(IrrNoApprovalError);
    expect(() => scoped(sign(base({ vessel_id: null })), { vessel_id: null })).toThrow(IrrNoApprovalError);
  });

  it('GH-253: scoped — a field every object has does not match by inheritance', () => {
    expect(() => scoped(sign(base()), { constructor: Object })).toThrow(IrrNoApprovalError);
    expect(() => scoped(sign(base()), { toString: Object.prototype.toString })).toThrow(IrrNoApprovalError);
  });

  it('GH-254: scoped — the scope must be an object of fields', () => {
    for (const s of [null, undefined, 'vessel_id', ['vessel_id'], 7]) {
      expect(() => scoped(sign(base()), s)).toThrow(IrrNoApprovalError);
    }
  });

  it('GH-255: scoped — matching text, number, boolean and 0 are accepted; a near miss is not', () => {
    const t = () => sign(base({ vessel_id: 'V1', amount: 100, urgent: false, zero: 0 }));
    expect(scoped(t(), { vessel_id: 'V1', amount: 100, urgent: false, zero: 0 }).vessel_id).toBe('V1');
    expect(() => scoped(t(), { amount: '100' })).toThrow(IrrNoApprovalError);
    expect(() => scoped(t(), { vessel_id: 'V1', amount: 101 })).toThrow(IrrNoApprovalError);
  });

  it('GH-256: a failed verify — the receipt is short and neither it nor the error holds the token', () => {
    const seen: AccReceipt[] = [];
    setEventBus({ emit: (r) => { seen.push(r); } });
    const t = sign(base({ service_id: 'A'.repeat(20000) }));
    let msg = '';
    try { verify(t); } catch (e) { msg = (e as Error).message; }
    expect(seen.length).toBe(1);
    expect(seen[0].verdict).toBe('FAIL');
    expect(String(seen[0].summary).length).toBeLessThan(400);
    expect(JSON.stringify(seen)).not.toContain(t);
    expect(msg).not.toContain(t);
    expect(msg.length).toBeLessThan(600);
  });

  it('GH-257: a bus that throws changes no verdict', () => {
    setEventBus({ emit: () => { throw new Error('bus down'); } });
    expect(verify(sign(base())).service_id).toBe('svc');
    expect(() => verify(sign(base({ expires_at: Date.now() - 1 })))).toThrow(IrrNoApprovalError);
  });
});

// ─── §H3 nonce ────────────────────────────────────────────────────────────────

describe('§H3 nonce — one use only (AEG-HG-2B-006, AEG-HG-2B-008)', () => {
  const refusedPayloads: [string, unknown][] = [
    ['null', null], ['text', 'token'], ['a list', []],
    ['no nonce', without(base(), 'nonce')], ['empty nonce', base({ nonce: '' })],
    ['nonce an object', base({ nonce: { id: 7 } })], ['nonce a number', base({ nonce: 12345 })],
    ['nonce true', base({ nonce: true })], ['nonce a list', base({ nonce: ['a'] })],
    ['no expiry', without(base(), 'expires_at')], ['expiry Infinity', base({ expires_at: Infinity })],
    ['already expired', base({ expires_at: Date.now() - 1000 })],
  ];
  for (const [name, p] of refusedPayloads) {
    it(`GH-3xx refused with the package's own error: ${name}`, async () => {
      let err: unknown;
      try { await verifyAndConsumeNonce(p as any, memStore()); } catch (e) { err = e; }
      expect(err).toBeInstanceOf(IrrNoApprovalError);
    });
  }

  it('GH-350: only a store that answers exactly true has consumed the nonce', async () => {
    for (const answer of [1, 'true', undefined, null, {}, false]) {
      let err: unknown;
      try { await verifyAndConsumeNonce(base() as any, { consumeNonce: async () => answer as any }); } catch (e) { err = e; }
      expect(err).toBeInstanceOf(IrrNoApprovalError);
    }
    await verifyAndConsumeNonce(base() as any, { consumeNonce: async () => true });
  });

  it('GH-351: an expired approval does not reach the store', async () => {
    let n = 0;
    try { await verifyAndConsumeNonce(base({ expires_at: Date.now() - 1 }) as any, { consumeNonce: async () => { n++; return true; } }); } catch { /* refused */ }
    expect(n).toBe(0);
  });

  it('GH-352: a store that is down propagates its own error (fail closed)', async () => {
    let err: unknown;
    try { await verifyAndConsumeNonce(base() as any, { consumeNonce: async () => { throw new Error('redis down'); } }); } catch (e) { err = e; }
    expect((err as Error).message).toBe('redis down');
  });

  it('GH-353: default store — ten uses at once, exactly one passes; a use after expiry is refused', async () => {
    const p = base({ expires_at: Date.now() + 60 }) as any;
    const r = await Promise.allSettled(Array.from({ length: 10 }, () => verifyAndConsumeNonce(p)));
    expect(r.filter((x) => x.status === 'fulfilled').length).toBe(1);
    await new Promise((res) => setTimeout(res, 100));
    let err: unknown;
    try { await verifyAndConsumeNonce(p); } catch (e) { err = e; }
    expect(err).toBeInstanceOf(IrrNoApprovalError);
  });

  it('GH-354: what verifyApprovalToken returns goes straight in', async () => {
    await verifyAndConsumeNonce(verify(sign(base())), memStore());
  });
});

// ─── §H4 duplicate ────────────────────────────────────────────────────────────

describe('§H4 duplicate check and fingerprint (AEG-HG-2B-009)', () => {
  it('GH-401: a duplicate is safe only when both fingerprints are known and equal', () => {
    expect(checkIdempotency('r', { id: 1 }, 'fp', 'fp')).toEqual({ isDuplicate: true, payloadMismatch: false, safeNoOp: true, comparable: true });
    expect(checkIdempotency('r', { id: 1 }, 'fp', 'other')).toEqual({ isDuplicate: true, payloadMismatch: true, safeNoOp: false, comparable: true });
    for (const [a, b] of [['fp', undefined], ['fp', null], ['fp', ''], [undefined, 'fp'], ['', ''], [{}, {}]] as any[]) {
      const r = checkIdempotency('r', { id: 1 }, a, b);
      expect(r.isDuplicate).toBe(true);
      expect(r.comparable).toBe(false);
      expect(r.safeNoOp).toBe(false);
    }
  });

  it('GH-402: no record is not a duplicate; a record that is 0 or "" is one', () => {
    expect(checkIdempotency('r', null, 'fp').isDuplicate).toBe(false);
    expect(checkIdempotency('r', undefined, 'fp').isDuplicate).toBe(false);
    expect(checkIdempotency('r', 0, 'fp', 'fp').isDuplicate).toBe(true);
    expect(checkIdempotency('r', '', 'fp', 'fp').isDuplicate).toBe(true);
  });

  it('GH-403: the unverifiable case is a WARN receipt of its own', () => {
    const seen: AccReceipt[] = [];
    setEventBus({ emit: (r) => { seen.push(r); } });
    checkIdempotency('r', { id: 1 }, 'fp');
    expect(seen[0].event_type).toBe('lock.idempotency.unverifiable');
    expect(seen[0].verdict).toBe('WARN');
    expect(() => checkIdempotency({} as any, { id: 1 }, 'fp', 'fp')).not.toThrow();
  });

  it('GH-404: a flat payload fingerprints exactly as it did in 0.3.1', () => {
    const p = { b: 'x', a: 1, c: null, d: true, e: 1.5 };
    const old = Buffer.from(JSON.stringify({ a: 1, b: 'x', c: null, d: true, e: 1.5 })).toString('base64');
    expect(buildIdempotencyFingerprint(p)).toBe(old);
  });

  it('GH-405: key order does not matter at any depth; list order does', () => {
    expect(buildIdempotencyFingerprint({ a: { b: { c: 1, d: 2 }, e: 3 } })).toBe(buildIdempotencyFingerprint({ a: { e: 3, b: { d: 2, c: 1 } } }));
    expect(buildIdempotencyFingerprint({ a: [1, 2] })).not.toBe(buildIdempotencyFingerprint({ a: [2, 1] }));
  });

  it('GH-406: values JSON cannot carry stay distinct from each other and from look-alikes', () => {
    const f = buildIdempotencyFingerprint;
    const all = [f({ a: NaN }), f({ a: null }), f({ a: Infinity }), f({ a: -Infinity }), f({ a: 1n }), f({ a: 1 }), f({ a: '1' }),
      f({ a: { $bigint: '1' } }), f({ a: { $number: 'NaN' } }), f({ a: new Map([[1, 2]]) }), f({ a: {} }), f({ a: new Set([1]) }),
      f({ a: 9007199254740993n }), f({ a: 9007199254740992n })];
    expect(new Set(all).size).toBe(all.length);
  });

  it('GH-407: a payload that contains itself is a plain error; a shared inner object is fine', () => {
    const loop: any = { a: 1 }; loop.self = loop;
    expect(() => buildIdempotencyFingerprint(loop)).toThrow(/refers to itself/);
    const inner = { x: 1 };
    expect(typeof buildIdempotencyFingerprint({ a: inner, b: inner })).toBe('string');
  });

  it('GH-408: a value whose toJSON returns itself finishes', () => {
    const v: any = { x: 1 }; v.toJSON = () => v;
    expect(typeof buildIdempotencyFingerprint({ a: v })).toBe('string');
  });

  it('GH-409: the payload must be an object of fields', () => {
    for (const p of [null, undefined, [1, 2], 'text', 7]) {
      expect(() => buildIdempotencyFingerprint(p as any)).toThrow(/must be an object/);
    }
  });
});

// ─── §H5 audit event ──────────────────────────────────────────────────────────

describe('§H5 the audit event never holds the token (AEG-HG-2B-005)', () => {
  const ev = (over: Record<string, unknown> = {}) => ({
    event_type: 'x', service_id: 'svc', capability: 'settle', operation: 'o',
    before_snapshot: {}, after_snapshot: {}, delta: {}, emitted_at: new Date().toISOString(),
    irreversible: true, correlation_id: 'c', ...over,
  }) as any;
  const emit = (e: any) => { let seen: any; const got: AccReceipt[] = []; configureSenseTransport((x) => { seen = x; }); setEventBus({ emit: (r) => { got.push(r); } }); emitAegisSenseEvent(e); return { seen, got }; };

  it('GH-501: a raw token given as the reference becomes its digest, in the event and the receipt', () => {
    const t = sign(base());
    const { seen, got } = emit(ev({ approval_token_ref: t }));
    expect(seen.approval_token_ref).toBe(digestApprovalToken(t));
    expect(JSON.stringify(seen)).not.toContain(t);
    expect(JSON.stringify(got)).not.toContain(t);
    expect(got[0].payload?.approval_token_ref).toBe(digestApprovalToken(t));
  });

  it('GH-502: a digest is passed through; the caller\'s object is not altered', () => {
    const d = digestApprovalToken('abc');
    expect(emit(ev({ approval_token_ref: d })).seen.approval_token_ref).toBe(d);
    const t = sign(base());
    const mine = ev({ approval_token_ref: t });
    emit(mine);
    expect(mine.approval_token_ref).toBe(t);
  });

  it('GH-503: a reference that is not text is digested too; an empty one is left out', () => {
    const t = sign(base());
    expect(JSON.stringify(emit(ev({ approval_token_ref: [t] })).seen)).not.toContain(t);
    expect('approval_token_ref' in emit(ev({ approval_token_ref: '' })).seen).toBe(false);
    expect('approval_token_ref' in emit(ev()).seen).toBe(false);
  });

  it('GH-504: every other field reaches the transport as given', () => {
    const e = ev({ delta: { status: 'a→b' }, idempotency_key: 'k', gate_phase: 'soak' });
    expect(emit(e).seen).toEqual(e);
  });
});

// ─── §H6 quality bar ──────────────────────────────────────────────────────────

describe('§H6 the quality bar reads a mask strictly (AEG-Q-003)', () => {
  it('GH-601: each group is met by exactly its bits and by all twelve, and not with one missing', () => {
    for (const [k, m] of Object.entries(HG_REQUIRED_MASKS)) {
      expect(meetsHgQualityRequirement(k as any, m)).toBe(true);
      expect(meetsHgQualityRequirement(k as any, 0x0fff)).toBe(true);
      expect(meetsHgQualityRequirement(k as any, m & (m - 1))).toBe(false);
    }
  });

  it('GH-602: anything that is not a whole number of bits 0-11 meets no bar', () => {
    for (const m of [-1, '4095', 4095.9, 0x1fff, 0x1000, 2 ** 32 + 4095, Infinity, NaN, 4095n, new Number(4095), [4095], true, null, undefined]) {
      expect(meetsHgQualityRequirement('HG-1', m as any)).toBe(false);
      expect(meetsHgQualityRequirement('HG-2B-financial', m as any)).toBe(false);
    }
  });

  it('GH-603: a group that is not in the table meets nothing', () => {
    for (const grp of ['HG-9', 'constructor', '__proto__', 'hasOwnProperty', ['HG-1'], null, undefined]) {
      expect(meetsHgQualityRequirement(grp as any, 0x0fff)).toBe(false);
    }
  });

  it('GH-604: the exported table cannot be changed', () => {
    expect(Object.isFrozen(HG_REQUIRED_MASKS)).toBe(true);
    try { (HG_REQUIRED_MASKS as any)['HG-2B-financial'] = 0; } catch { /* strict mode throws */ }
    expect(HG_REQUIRED_MASKS['HG-2B-financial']).toBe(0x0fff);
    expect(meetsHgQualityRequirement('HG-2B-financial', 0)).toBe(false);
  });

  it('GH-605: no evidence, no bits', () => {
    for (const e of [null, undefined, 'x', 7]) {
      expect(buildQualityMaskAtPromotion(e as any)).toBe(0);
      expect(buildQualityDriftScore(e as any)).toBe(0);
    }
    expect(buildQualityMaskAtPromotion({ tests_passed: 'true', human_reviewed: 1 } as any)).toBe(0);
  });
});

// ─── §H7 envelope ─────────────────────────────────────────────────────────────

describe('§H7 the envelope helpers read the answer strictly (ASE-016)', () => {
  const realFetch = globalThis.fetch;
  let calls: string[] = [];
  const stub = (status: number, body: unknown) => {
    calls = [];
    globalThis.fetch = (async (u: any) => { calls.push(String(u)); return new Response(typeof body === 'string' ? body : JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } }); }) as typeof fetch;
  };
  afterEach(() => { globalThis.fetch = realFetch; });
  const A = { aegis_url: 'http://aegis.invalid' };

  it('GH-701: verified only when the answer says exactly true', async () => {
    stub(200, { session_id: 's1', sealed_hash_verified: true, drift_detected: false, drift_set: [] });
    const good = await verifyEnvelope('s1', A);
    expect(good.verified).toBe(true);
    expect(good.drift_detected).toBe(false);
    for (const v of [false, 'false', 'true', 'tampered', 1, null, undefined, {}]) {
      stub(200, { session_id: 's1', sealed_hash_verified: v });
      expect((await verifyEnvelope('s1', A)).verified).toBe(false);
    }
  });

  it('GH-702: the audit must be for the session asked about', async () => {
    stub(200, { session_id: 'someone-else', sealed_hash_verified: true });
    await expect(verifyEnvelope('s1', A)).rejects.toThrow(/another session/);
    stub(200, { sealed_hash_verified: true });
    await expect(verifyEnvelope('s1', A)).rejects.toThrow(/another session/);
  });

  it('GH-703: drift unless the answer says exactly false and the list is empty', async () => {
    const drift = async (body: Record<string, unknown>) => { stub(200, { session_id: 's1', sealed_hash_verified: true, ...body }); return (await verifyEnvelope('s1', A)).drift_detected; };
    expect(await drift({ drift_detected: false, drift_set: [] })).toBe(false);
    expect(await drift({})).toBe(false);
    expect(await drift({ drift_detected: false, drift_set: ['shell'] })).toBe(true);
    expect(await drift({ drift_detected: 'false', drift_set: [] })).toBe(true);
    expect(await drift({ drift_detected: false, drift_set: 'shell,net' })).toBe(true);
    expect(await drift({ drift_detected: true })).toBe(true);
  });

  it('GH-704: an answer that is an error, or not an object, throws a plain error', async () => {
    for (const body of [{ ok: false, error: 'session not found' }, null, 'text']) {
      stub(200, body === 'text' ? '"text"' : body);
      await expect(verifyEnvelope('s1', A)).rejects.toThrow(/verifyEnvelope failed/);
      stub(200, body === 'text' ? '"text"' : body);
      await expect(issueEnvelope(A)).rejects.toThrow(/issueEnvelope failed/);
    }
    stub(500, 'down');
    await expect(verifyEnvelope('s1', A)).rejects.toThrow(/500/);
  });

  it('GH-705: issue — no session id or no seal is not an envelope', async () => {
    for (const body of [{}, { session_id: 's' }, { sealed_hash: 'h' }, { session_id: 42, sealed_hash: 'h' }, { session_id: 's', sealed_hash: '' }]) {
      stub(200, body);
      await expect(issueEnvelope(A)).rejects.toThrow(/no session_id or no sealed_hash/);
    }
    stub(200, { ok: true, session_id: 's9', agent_id: 'a9', sealed_hash: 'h9', perm_mask: 3, class_mask: 1, declared_caps: ['x'] });
    const r = await issueEnvelope(A);
    expect(r).toMatchObject({ session_id: 's9', agent_id: 'a9', sealed_hash: 'h9', perm_mask: 3, class_mask: 1, declared_caps: ['x'] });
  });

  it('GH-706: only http and https addresses are fetched', async () => {
    stub(200, { session_id: 's1', sealed_hash_verified: true });
    for (const url of ['file:///tmp/aegis', 'data:application/json,{}', 'not a url']) {
      await expect(verifyEnvelope('s1', { aegis_url: url })).rejects.toThrow(/aegis-guard/);
      await expect(issueEnvelope({ aegis_url: url })).rejects.toThrow(/aegis-guard/);
    }
    expect(calls.length).toBe(0);
  });

  it('GH-707: the session id is one path part; the budget is read from the audit route\'s names', async () => {
    stub(200, { session_id: 'a/../b', sealed_hash_verified: true, budget_allocated: 5, budget_used: 2 });
    const r = await verifyEnvelope('a/../b', A);
    expect(calls[0]).toContain('a%2F..%2Fb');
    expect(r.budget_usd).toBe(5);
    expect(r.budget_used_usd).toBe(2);
  });
});

// ─── §H8 limits ───────────────────────────────────────────────────────────────
// Each of these is a thing the package does NOT do. They are tests so that the README's
// list of limits cannot drift from the code without a test changing.

describe('§H8 stated limits', () => {
  it('LIMIT: there is no upper limit on a token\'s life', () => {
    expect(verify(sign(base({ expires_at: Date.now() + 10 * 365 * 86_400_000 }))).service_id).toBe('svc');
  });

  it('LIMIT: an empty scope checks nothing more than verifyApprovalToken', () => {
    expect(scoped(sign(base()), {}).service_id).toBe('svc');
  });

  it('LIMIT: a scope value that is an object never matches, even an equal one', () => {
    expect(() => scoped(sign(base({ dims: { w: 1 } })), { dims: { w: 1 } })).toThrow(IrrNoApprovalError);
  });

  it('LIMIT: verifyAndConsumeNonce checks no signature and no status', async () => {
    await verifyAndConsumeNonce({ service_id: 'x', capability: 'y', operation: 'z', nonce: 'made-up', expires_at: Date.now() + 1000, status: 'revoked' } as any, memStore());
  });

  it('LIMIT: a key FILE swapped under a running process is not noticed until restart', () => {
    const d = box({ pub: AUTH_PUB });
    const t = sign(base());
    expect(verify(t, d).service_id).toBe('svc');
    writeFileSync(join(d, 'approval-signing.pub'), OTHER_PUB);
    process.env.AEGIS_DIR = d; // same directory, no reload
    try { expect(verifyApprovalToken(t, 'svc', 'settle', 'record_settle').service_id).toBe('svc'); } finally { process.env.AEGIS_DIR = AUTH; }
  });

  it('LIMIT: the fingerprint is the payload, encoded, not a hash', () => {
    expect(Buffer.from(buildIdempotencyFingerprint({ card: '4111-1111' }), 'base64').toString()).toBe('{"card":"4111-1111"}');
  });

  it('LIMIT: a field set to undefined fingerprints as the field absent; a Date as its ISO text', () => {
    expect(buildIdempotencyFingerprint({ a: 1, b: undefined })).toBe(buildIdempotencyFingerprint({ a: 1 }));
    expect(buildIdempotencyFingerprint({ at: new Date(0) })).toBe(buildIdempotencyFingerprint({ at: '1970-01-01T00:00:00.000Z' }));
  });

  it('LIMIT: a raw token anywhere but the reference field reaches the transport', () => {
    const t = sign(base());
    let seen: any;
    configureSenseTransport((x) => { seen = x; });
    emitAegisSenseEvent({ event_type: 'x', service_id: 's', capability: 'c', operation: 'o', before_snapshot: {}, after_snapshot: {}, delta: { token: t }, emitted_at: '', irreversible: false, correlation_id: 'c' });
    expect(JSON.stringify(seen)).toContain(t);
  });

  it('LIMIT: a SENSE transport that throws reaches the caller; snapshots are not checked', () => {
    configureSenseTransport(() => { throw new Error('logger down'); });
    expect(() => emitAegisSenseEvent({ event_type: 'x', service_id: 's', capability: 'c', operation: 'o', before_snapshot: {}, after_snapshot: {}, delta: {}, emitted_at: '', irreversible: false, correlation_id: 'c' })).toThrow('logger down');
    let n = 0;
    configureSenseTransport(() => { n++; });
    emitAegisSenseEvent({ event_type: 'x', service_id: 's', capability: 'c', operation: 'o', emitted_at: '', irreversible: true, correlation_id: 'c' } as any);
    expect(n).toBe(1);
  });

  it('LIMIT: the envelope helpers take class_mask 0xFFFF and budget 0 when the answer gives none', async () => {
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async () => new Response(JSON.stringify({ session_id: 's', sealed_hash: 'h' }), { status: 200 })) as typeof fetch;
    try {
      const r = await issueEnvelope({ aegis_url: 'http://aegis.invalid' });
      expect(r.class_mask).toBe(0xffff);
      expect(r.budget_usd).toBe(0);
    } finally { globalThis.fetch = realFetch; }
  });
});
