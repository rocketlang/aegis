// @rule:AEG-E-016 — approval tokens are AEGIS-signed; an unsigned approval is a forgery
// @rule:KGT-002 — fail-closed: no key material → verification DENIES, never falls open
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

// Cache keyed by resolved dir so tests (which point AEGIS_DIR at a temp dir) and
// long-lived services both get one disk read, not one per verify.
let cache: { dir: string; priv: KeyObject | null; pub: KeyObject | null } | null = null;

function loadKeys(): { priv: KeyObject | null; pub: KeyObject | null } {
  const dir = aegisDir();
  if (cache && cache.dir === dir) return cache;

  let priv: KeyObject | null = null;
  let pub: KeyObject | null = null;

  const keyPath = join(dir, KEY_FILE);
  if (existsSync(keyPath)) {
    try {
      priv = createPrivateKey(readFileSync(keyPath, 'utf8'));
      pub = createPublicKey(priv);
    } catch { priv = null; pub = null; }
  }

  // Verifier-only deployments: public key via env PEM or the .pub file.
  if (!pub) {
    const envPem = process.env.AEGIS_APPROVAL_PUBKEY_PEM;
    const pubPath = join(dir, PUB_FILE);
    try {
      if (envPem) pub = createPublicKey(envPem);
      else if (existsSync(pubPath)) pub = createPublicKey(readFileSync(pubPath, 'utf8'));
    } catch { pub = null; }
  }

  cache = { dir, priv, pub };
  return cache;
}

// Generate the per-machine keypair if absent. Called lazily by the mint path and by
// the AEGIS dashboard at boot (the authority guarantees the key exists on its box).
export function ensureSigningKeypair(): { publicKeyPem: string } {
  const dir = aegisDir();
  const keyPath = join(dir, KEY_FILE);
  const pubPath = join(dir, PUB_FILE);

  if (!existsSync(keyPath)) {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    writeFileSync(keyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
    writeFileSync(pubPath, publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o644 });
    cache = null;
  } else if (!existsSync(pubPath)) {
    // key exists but pub was lost — re-derive, never regenerate (verifiers may hold the pub)
    const priv = createPrivateKey(readFileSync(keyPath, 'utf8'));
    writeFileSync(pubPath, createPublicKey(priv).export({ type: 'spki', format: 'pem' }), { mode: 0o644 });
    cache = null;
  }

  const { pub } = loadKeys();
  return { publicKeyPem: pub!.export({ type: 'spki', format: 'pem' }).toString() };
}

export function getPublicKeyPem(): string | null {
  const { pub } = loadKeys();
  return pub ? pub.export({ type: 'spki', format: 'pem' }).toString() : null;
}

function b64url(buf: Buffer | string): string {
  return Buffer.from(buf).toString('base64url');
}

// Sign a payload as a compact EdDSA JWT: b64url(header).b64url(payload).b64url(sig).
// Throws if no private key — only the AEGIS box (or a box it provisioned) can mint.
export function signApprovalJwt(payload: Record<string, unknown>): string {
  ensureSigningKeypair();
  const { priv } = loadKeys();
  if (!priv) {
    throw new Error(
      'KGT-002: no AEGIS approval signing key — cannot mint (fail-closed). ' +
      `Expected ${join(aegisDir(), KEY_FILE)}; the AEGIS dashboard (:4850) provisions it at boot.`,
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
    alg = (JSON.parse(Buffer.from(header, 'base64url').toString('utf8')) as { alg?: unknown }).alg;
  } catch {
    return { ok: false, reason: 'malformed token: header is not base64url JSON' };
  }
  if (alg !== APPROVAL_JWT_ALG) {
    return { ok: false, reason: `alg '${String(alg)}' rejected — only ${APPROVAL_JWT_ALG} approvals are trusted` };
  }

  const { pub } = loadKeys();
  if (!pub) {
    return {
      ok: false,
      reason: 'KGT-002: no AEGIS public key available — verification fails closed. ' +
        'Provision ~/.aegis/approval-signing.pub or set AEGIS_APPROVAL_PUBKEY_PEM ' +
        '(GET :4850/api/v2/enforcement/signing-key).',
    };
  }

  let valid = false;
  try {
    valid = edVerify(null, Buffer.from(`${header}.${body}`), pub, Buffer.from(sig, 'base64url'));
  } catch {
    valid = false;
  }
  if (!valid) return { ok: false, reason: 'signature invalid — token was not minted by AEGIS' };

  try {
    return { ok: true, payload: JSON.parse(Buffer.from(body, 'base64url').toString('utf8')) };
  } catch {
    return { ok: false, reason: 'malformed token: payload is not base64url JSON' };
  }
}

// test-only: drop the key cache so a test can swap AEGIS_DIR mid-suite
export function __resetSigningCache(): void {
  cache = null;
}
