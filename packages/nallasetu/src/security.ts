// SPDX-License-Identifier: AGPL-3.0-only
// Nallasetu — who may reach the listener (0.4.0).
//
// Through 0.3.0 the server listened on every interface and no route asked who was calling. Anyone who
// could reach the port could read a session by its id, revoke it, run the expire-stale maintenance call,
// and have a session issued for any new name (the engine registers an unknown initiator and signs for it).
//
// Now the defaults are closed, the same way as @xshieldai/varuna:
//   - listen on 127.0.0.1 unless NALLASETU_HOST is set;
//   - with NALLASETU_API_TOKEN set, every route but /health needs `Authorization: Bearer <token>`;
//   - reachable off this machine with no token: the server REFUSES TO START, unless the operator sets
//     NALLASETU_ALLOW_OPEN=1 to accept an open listener knowingly;
//   - cross-origin requests are off unless NALLASETU_CORS_ORIGIN names an origin.
//
// Pure decisions, so they can be tested without starting the service.
import { timingSafeEqual } from "crypto";

export type Env = Record<string, string | undefined>;

export const TOKEN_MIN = 24;

export const isLoopbackHost = (host: string): boolean =>
  host === "127.0.0.1" || host === "::1" || host === "localhost" || host === "[::1]";

export const resolveHost = (env: Env): string => env.NALLASETU_HOST?.trim() || "127.0.0.1";

export const resolveCorsOrigin = (env: Env): string | false =>
  env.NALLASETU_CORS_ORIGIN !== undefined && env.NALLASETU_CORS_ORIGIN.trim() !== "" ? env.NALLASETU_CORS_ORIGIN.trim() : false;

const envTrue = (v?: string): boolean => v === "1" || v === "true" || v === "yes";

export interface AuthDecision {
  mode: "token" | "open" | "refuse";
  token?: string;
  reason?: string;
}

export function resolveAuth(env: Env, host: string): AuthDecision {
  const token = env.NALLASETU_API_TOKEN;
  if (token !== undefined && token !== "") {
    if (token.length < TOKEN_MIN || /\s/.test(token)) {
      return { mode: "refuse", reason: `NALLASETU_API_TOKEN must be at least ${TOKEN_MIN} characters with no spaces (try: openssl rand -hex 24)` };
    }
    return { mode: "token", token };
  }
  if (isLoopbackHost(host)) return { mode: "open", reason: "listening on this machine only" };
  if (envTrue(env.NALLASETU_ALLOW_OPEN)) {
    return { mode: "open", reason: `NALLASETU_ALLOW_OPEN set: an unauthenticated listener on ${host}, by explicit choice` };
  }
  return {
    mode: "refuse",
    reason:
      `Nallasetu would be reachable on ${host} with no authentication: anyone could read or revoke a session, ` +
      `or have one issued. Set NALLASETU_API_TOKEN to require a bearer token, or NALLASETU_HOST=127.0.0.1, or ` +
      `NALLASETU_ALLOW_OPEN=1 to accept an open listener knowingly.`,
  };
}

/** Decided on the route the server matched, never on the request address. */
export const isPublicRoute = (method: string, route: string | undefined): boolean =>
  route === "/health" || (method === "OPTIONS" && route === "*");

export function tokenMatches(authorization: unknown, token: string): boolean {
  if (typeof authorization !== "string" || !authorization.startsWith("Bearer ")) return false;
  const given = Buffer.from(authorization.slice(7), "utf8"), want = Buffer.from(token, "utf8");
  return given.length === want.length && timingSafeEqual(given, want);
}
