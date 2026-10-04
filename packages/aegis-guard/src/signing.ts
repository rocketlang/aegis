// @rule:AEG-E-016 — approval tokens are AEGIS-signed; an unsigned approval is a forgery
// @rule:KGT-002 — fail-closed: no key material → verification DENIES, never falls open
// @rule:AEG-HG-2B-007 — a box that was given a public key to trust never makes a key of its own,
//                 and a box whose configured keys disagree trusts none of them
//
// KGT-T1.1 — Ed25519 JWT signing for approval tokens.
// Before this module, mintApprovalToken emitted base64url(JSON): any client could
// fabricate an "approval". Now AEGIS (:4850, the minting authority) holds the private
// key; every verifier needs only the public key. Same key-management pattern as
// kernel/mudrika.ts: persistent per-machine key material under ~/.aegis, mode 600,
// generated once. Zero-dep — node:crypto ed25519 only.

import {
  generateKeyPairSync,
  createPrivateKey,
  createPublicKey,
  sign as edSign,
  verify as edVerify,
  type KeyObject,
} from 'crypto';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

export const APPROVAL_JWT_ALG = 'EdDSA';

const KEY_FILE = 'approval-signing.key'; // PKCS8 PEM (private) — mode 600
const PUB_FILE = 'approval-signing.pub'; // SPKI PEM (public) — mode 644

function aegisDir(): string {
  return process.env.AEGIS_DIR ?? join(process.env.HOME ?? homedir(), '.aegis');
}

// Cache keyed by resolved dir and by the environment key, so tests (which point AEGIS_DIR
// at a temp dir) and long-lived services both get one disk read, not one per verify.
// A key FILE that changes under a running process is not noticed until restart.
interface Keys {
  dir: string;
  env: string;
  priv: KeyObject | null;
  pub: KeyObject | null;
  /** Why no key is trusted although key material exists. */
  conflict: string | null;
}
let cache: Keys | null = null;

const pemOf = (k: KeyObject): string => k.export({ type: 'spki', format: 'pem' }).toString();

function loadKeys(): Keys {
  const dir = aegisDir();
  const envPem = process.env.AEGIS_APPROVAL_PUBKEY_PEM ?? '';
  if (cache && cache.dir === dir && cache.env === envPem) return cache;

  let priv: KeyObject | null = null;
  let pub: KeyObject | null = null;
  let conflict: string | null = null;

  const keyPath = join(dir, KEY_FILE);
  const pubPath = join(dir, PUB_FILE);

  if (existsSync(keyPath)) {
    try {
      priv = createPrivateKey(readFileSync(keyPath, 'utf8'));
      if (priv.asymmetricKeyType !== 'ed25519') throw new Error('not an ed25519 key');
      pub = createPublicKey(priv);
    } catch {
      priv = null; pub = null;
      conflict = `${KEY_FILE} exists but is not a usable Ed25519 private key`;
    }
  }

  // Every public key this box has been told about: the file, and the environment.
  const told: Array<[string, KeyObject]> = [];
  if (existsSync(pubPath)) {
    try { told.push([PUB_FILE, createPublicKey(readFileSync(pubPath, 'utf8'))]); }
    catch { conflict ??= `${PUB_FILE} exists but is not a usable public key`; }
  }
  if (envPem) {
    try { told.push(['AEGIS_APPROVAL_PUBKEY_PEM', createPublicKey(envPem)]); }
    catch { conflict ??= 'AEGIS_APPROVAL_PUBKEY_PEM is set but is not a usable public key'; }
  }

  // @rule:AEG-HG-2B-007 — all of them must be the same Ed25519 key. If the private key and a
  // public key the box was told about disagree, one of them was replaced, and the box
  // cannot know which: it trusts none.
  for (const [name, k] of told) {
    if (k.asymmetricKeyType !== 'ed25519') { conflict ??= `${name} is not an Ed25519 key`; continue; }
    if (!pub) pub = k;
    else if (pemOf(pub) !== pemOf(k)) conflict ??= `${name} is a different key from the other key material on this box`;
  }
  if (conflict) { priv = null; pub = null; }

  cache = { dir, env: envPem, priv, pub, conflict };
  return cache;
}

// Generate the per-machine keypair if absent. Called by the AEGIS dashboard at boot: the
// authority guarantees the key exists on its box. It is NOT called by the mint path.
//
// @rule:AEG-HG-2B-007 — it refuses on a box that already trusts a public key (the file, or the
// environment) and has no private key. Such a box is a verifier. Making a key there would
// replace the authority's key with the box's own, and the box would then accept approvals
// it signed itself.
export function ensureSigningKeypair(): { publicKeyPem: string } {
  const dir = aegisDir();
  const keyPath = join(dir, KEY_FILE);
  const pubPath = join(dir, PUB_FILE);

  if (!existsSync(keyPath)) {
    if (existsSync(pubPath) || process.env.AEGIS_APPROVAL_PUBKEY_PEM) {
      throw new Error(
        'AEG-HG-2B-007: this box holds a public approval key and no private key — it verifies, it ' +
        'does not sign. Refusing to generate a keypair over the key it was given.',
      );
    }
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    // 'wx': never write over a key another process made between the check and here.
    writeFileSync(keyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600, flag: 'wx' });
    writeFileSync(pubPath, publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o644 });
    cache = null;
  } else if (!existsSync(pubPath)) {
    // key exists but pub was lost — re-derive, never regenerate (verifiers may hold the pub)
    const priv = createPrivateKey(readFileSync(keyPath, 'utf8'));
    writeFileSync(pubPath, createPublicKey(priv).export({ type: 'spki', format: 'pem' }), { mode: 0o644 });
    cache = null;
  }

  const { pub, conflict } = loadKeys();
  if (!pub) throw new Error(`AEG-HG-2B-007: no usable approval signing key${conflict ? ` — ${conflict}` : ''}`);
  return { publicKeyPem: pemOf(pub) };
}

export function getPublicKeyPem(): string | null {
  const { pub } = loadKeys();
  return pub ? pemOf(pub) : null;
}

function b64url(buf: Buffer | string): string {
  return Buffer.from(buf).toString('base64url');
}

// Sign a payload as a compact EdDSA JWT: b64url(header).b64url(payload).b64url(sig).
// Throws if no private key — only the AEGIS box (or a box it provisioned) can mint.
// It never makes a key: before v0.4.0 it did, on any box, at the first mint. The authority
// calls ensureSigningKeypair() once, at boot.
export function signApprovalJwt(payload: Record<string, unknown>): string {
  const { priv, conflict } = loadKeys();
  if (!priv) {
    throw new Error(
      'KGT-002: no AEGIS approval signing key — cannot mint (fail-closed). ' +
      (conflict ? `${conflict}. ` : '') +
      `Expected ${join(aegisDir(), KEY_FILE)}; the AEGIS dashboard (:4850) provisions it at boot ` +
      'with ensureSigningKeypair().',
    );
  }
  const header = b64url(JSON.stringify({ alg: APPROVAL_JWT_ALG, typ: 'JWT' }));
  const body = b64url(JSON.stringify(payload));
  const sig = edSign(null, Buffer.from(`${header}.${body}`), priv);
  return `${header}.${body}.${b64url(sig)}`;
}

export type JwtVerifyResult =
  | { ok: true; payload: Record<string, unknown> }
  | { ok: false; reason: string };

// Verify signature + structure ONLY (scope/expiry stay in approval-token.ts).
// Fail-closed on every path: malformed, wrong alg (alg:none forgery), bad signature,
// or no public key available at all.
export function verifyApprovalJwt(token: string): JwtVerifyResult {
  if (typeof token !== 'string' || token.length === 0) {
    return { ok: false, reason: 'malformed token: not text' };
  }
  const parts = token.split('.');
  if (parts.length !== 3) {
    return {
      ok: false,
      reason: parts.length === 1
        ? 'unsigned legacy token rejected — approval tokens are AEGIS-signed JWTs (KGT-T1.1)'
        : 'malformed token: expected 3 JWT segments',
    };
  }
  const [header, body, sig] = parts;

  let alg: unknown;
  try {
    const h: unknown = JSON.parse(Buffer.from(header, 'base64url').toString('utf8'));
    if (h === null || typeof h !== 'object' || Array.isArray(h)) throw new Error('not an object');
    alg = (h as { alg?: unknown }).alg;
  } catch {
    return { ok: false, reason: 'malformed token: header is not base64url JSON' };
  }
  if (alg !== APPROVAL_JWT_ALG) {
    return { ok: false, reason: `alg '${String(alg)}' rejected — only ${APPROVAL_JWT_ALG} approvals are trusted` };
  }

  const { pub, conflict } = loadKeys();
  if (!pub) {
    return {
      ok: false,
      reason: 'KGT-002: no AEGIS public key available — verification fails closed. ' +
        (conflict ? `AEG-HG-2B-007: ${conflict}. ` : '') +
        'Provision ~/.aegis/approval-signing.pub or set AEGIS_APPROVAL_PUBKEY_PEM ' +
        '(GET :4850/api/v2/enforcement/signing-key).',
    };
  }

  // One approval, one spelling: the signature segment must be exactly the 64 bytes in
  // base64url. The decoder ignores characters it does not know, so without this check
  // "<token>!!" would verify as well, as a second token with a different digest.
  const sigBytes = Buffer.from(sig, 'base64url');
  if (sigBytes.length !== 64 || sigBytes.toString('base64url') !== sig) {
    return { ok: false, reason: 'signature invalid — token was not minted by AEGIS' };
  }

  let valid = false;
  try {
    valid = edVerify(null, Buffer.from(`${header}.${body}`), pub, sigBytes);
  } catch {
    valid = false;
  }
  if (!valid) return { ok: false, reason: 'signature invalid — token was not minted by AEGIS' };

  try {
    const payload: unknown = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
      return { ok: false, reason: 'malformed token: payload is not a JSON object' };
    }
    return { ok: true, payload: payload as Record<string, unknown> };
  } catch {
    return { ok: false, reason: 'malformed token: payload is not base64url JSON' };
  }
}

// test-only: drop the key cache so a test can swap AEGIS_DIR mid-suite
export function __resetSigningCache(): void {
  cache = null;
}
