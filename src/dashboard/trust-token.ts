// AEGIS Dashboard — machine trust-token verification (Keeper Ed25519, zero external deps).
//
// A machine caller (e.g. the capability certifier) presents:
//   Authorization: Bearer <payload>.<sig>
// payload = base64url(JSON{ iss, trust_mask, scope, exp }); sig = Ed25519 over payload by the KEEPER key.
// Verified here with the Keeper PUBLIC key — only Keeper-signed tokens pass. This turns the machine
// path for Forja endpoints from an OPEN bypass into a trust-gated one: an agent cannot reach a
// safety-gated proof without a signed token (the "agents can bypass trust" hole, closed).

import { verify, createPublicKey, type KeyObject } from "crypto";
import { readFileSync, existsSync } from "fs";

const KEEPER_PUB = process.env.ANKR_KEEPER_PUB ?? "/root/.ankr/keys/keeper-ed25519.pub.pem";

let pub: KeyObject | null = null;
function keeperKey(): KeyObject | null {
  if (pub) return pub;
  if (!existsSync(KEEPER_PUB)) return null;
  try { pub = createPublicKey(readFileSync(KEEPER_PUB, "utf8")); return pub; } catch { return null; }
}

export function verifyTrustToken(authHeader: string | undefined): { valid: boolean; iss?: string; trust_mask?: number } {
  if (!authHeader) return { valid: false };
  const m = authHeader.match(/^Bearer\s+(.+)$/i);
  if (!m) return { valid: false };
  const key = keeperKey();
  if (!key) return { valid: false };
  const raw = m[1];
  const dot = raw.lastIndexOf(".");
  if (dot < 0) return { valid: false };
  const payload = raw.slice(0, dot);
  const sig = raw.slice(dot + 1);
  try {
    if (!verify(null, Buffer.from(payload), key, Buffer.from(sig, "base64url"))) return { valid: false };
    const c = JSON.parse(Buffer.from(payload, "base64url").toString());
    if (typeof c.exp === "number" && Date.now() > c.exp) return { valid: false };
    return { valid: true, iss: c.iss, trust_mask: c.trust_mask };
  } catch {
    return { valid: false };
  }
}
