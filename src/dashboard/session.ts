// AEGIS Dashboard — session management (HMAC-SHA256, no external deps)
// Cookie: aegis_sid=<base64(payload)>.<base64(sig)>
// Stateless — no session store needed. Valid for SESSION_TTL_MS.

import { createHmac, randomBytes } from "crypto";
import { readFileSync, writeFileSync, mkdirSync } from "fs";
import { dirname } from "path";
import { getAegisDir } from "../core/config";

const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 8 hours
const COOKIE_NAME = "aegis_sid";

let _secret: string | null = null;

// The secret the session cookie is signed with. An explicit AEGIS_SESSION_SECRET always
// wins (so several processes can share one). Otherwise a per-install secret is generated
// once and kept under ~/.aegis, so it is stable across restarts AND is not a value anyone
// can read. Before 2.7.0 the fallback was the fixed string "aegis-dashboard-session-v1",
// present in the public source, so where auth was on but no secret was set a cookie could
// be forged from it.
function getSecret(): string {
  const env = process.env.AEGIS_SESSION_SECRET;
  if (env && env.length > 0) return env;
  if (_secret) return _secret;
  const file = `${getAegisDir()}/session-secret`;
  try {
    const existing = readFileSync(file, "utf8").trim();
    if (existing) { _secret = existing; return _secret; }
  } catch { /* not yet written */ }
  _secret = randomBytes(32).toString("base64url");
  try {
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, _secret, { mode: 0o600 });
  } catch {
    // An unwritable ~/.aegis (read-only fs): keep the secret in memory for this process. It
    // is still random and unforgeable; cookies just do not outlive a restart. Never fall
    // back to a public constant.
  }
  return _secret;
}

function sign(payload: string): string {
  return createHmac("sha256", getSecret()).update(payload).digest("base64url");
}

export function issueSessionCookie(username: string): string {
  const payload = Buffer.from(
    JSON.stringify({ u: username, iat: Date.now() })
  ).toString("base64url");
  const sig = sign(payload);
  const value = `${payload}.${sig}`;
  const maxAge = SESSION_TTL_MS / 1000;
  return `${COOKIE_NAME}=${value}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
}

export function clearSessionCookie(): string {
  return `${COOKIE_NAME}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`;
}

export function verifySession(cookieHeader: string | undefined): { valid: boolean; username?: string } {
  if (!cookieHeader) return { valid: false };
  const match = cookieHeader.match(new RegExp(`(?:^|; )${COOKIE_NAME}=([^;]+)`));
  if (!match) return { valid: false };
  const raw = match[1];
  const dot = raw.lastIndexOf(".");
  if (dot < 0) return { valid: false };
  const payload = raw.slice(0, dot);
  const sig = raw.slice(dot + 1);
  if (sign(payload) !== sig) return { valid: false };
  try {
    const data = JSON.parse(Buffer.from(payload, "base64url").toString());
    if (Date.now() - data.iat > SESSION_TTL_MS) return { valid: false };
    return { valid: true, username: data.u };
  } catch {
    return { valid: false };
  }
}

export { COOKIE_NAME };
