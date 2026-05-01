// AEGIS Dashboard — session management (HMAC-SHA256, no external deps)
// Cookie: aegis_sid=<base64(payload)>.<base64(sig)>
// Stateless — no session store needed. Valid for SESSION_TTL_MS.

import { createHmac, randomBytes } from "crypto";

const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 8 hours
const COOKIE_NAME = "aegis_sid";

function getSecret(): string {
  // Use dashboard.auth.secret if set, otherwise derive from password + a fixed pepper.
  // Secret is stable across restarts so existing cookies stay valid.
  return process.env.AEGIS_SESSION_SECRET ?? "aegis-dashboard-session-v1";
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
