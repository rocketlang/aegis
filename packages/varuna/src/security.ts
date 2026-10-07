/**
 * Varuna listener security — safe by default (review finding "Varuna no-auth", 2026-10-08).
 *
 * Before: HOST defaulted to 0.0.0.0, CORS to '*', and ingest had no auth — an open, cross-origin,
 * unauthenticated writer reachable from any interface. Now the defaults are closed:
 *   - bind 127.0.0.1 unless HOST is set explicitly;
 *   - CORS off unless CORS_ORIGIN is set;
 *   - ingest (and every route but /health) requires a bearer token when one is configured, and the
 *     server REFUSES TO START if it would be reachable off-box with no token — unless an operator
 *     sets VARUNA_ALLOW_OPEN=1 to accept an open listener knowingly.
 *
 * Pure decisions here so they can be tested without booting the whole service.
 */

export type Env = Record<string, string | undefined>;

export const isLoopbackHost = (host: string): boolean =>
  host === '127.0.0.1' || host === '::1' || host === 'localhost' || host === '[::1]';

/** Bind loopback unless HOST is set. Exposing off-box is a deliberate act. */
export const resolveHost = (env: Env): string => env['HOST'] ?? '127.0.0.1';

/**
 * CORS is OFF by default (same-origin only). A deployment that needs a browser origin sets
 * CORS_ORIGIN explicitly; '*' is possible but only when asked for, never the default.
 */
export const resolveCorsOrigin = (env: Env): string | boolean =>
  env['CORS_ORIGIN'] !== undefined && env['CORS_ORIGIN'] !== '' ? env['CORS_ORIGIN']! : false;

const envTrue = (v?: string): boolean => v === '1' || v === 'true' || v === 'yes';

export interface AuthDecision {
  mode: 'token' | 'open-local' | 'refuse';
  token?: string;
  reason?: string;
}

/**
 * How the listener authenticates:
 *   token       — VARUNA_API_TOKEN is set; every route but /health needs `Authorization: Bearer <token>`.
 *   open-local   — no token, but bound to loopback (local-dev convenience) or VARUNA_ALLOW_OPEN set.
 *   refuse      — no token AND reachable off-box AND not explicitly opted open: do not start.
 */
export function resolveAuth(env: Env, host: string): AuthDecision {
  const token = env['VARUNA_API_TOKEN'];
  if (token !== undefined && token !== '') return { mode: 'token', token };
  if (isLoopbackHost(host)) return { mode: 'open-local' };
  if (envTrue(env['VARUNA_ALLOW_OPEN'])) {
    return { mode: 'open-local', reason: 'VARUNA_ALLOW_OPEN set — unauthenticated listener on a non-loopback host, by explicit choice' };
  }
  return {
    mode: 'refuse',
    reason:
      `Varuna would be reachable on ${host} with no authentication (ingest is a writer). ` +
      `Set VARUNA_API_TOKEN to require a bearer token, or bind HOST=127.0.0.1, or set ` +
      `VARUNA_ALLOW_OPEN=1 to accept an open listener knowingly.`,
  };
}

/** Routes that never need a token (liveness + CORS preflight). */
export const isPublicRoute = (method: string, url: string): boolean =>
  method === 'OPTIONS' || url === '/health' || url.startsWith('/health?');

/**
 * A fastify onRequest hook that requires `Authorization: Bearer <token>` on every non-public route.
 * Returns the hook, or null when no token is configured (open-local — nothing to enforce).
 */
export function makeAuthHook(token: string) {
  const expected = `Bearer ${token}`;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return async function authHook(request: any, reply: any) {
    if (isPublicRoute(request.method, request.url)) return;
    const given = request.headers?.['authorization'];
    if (given !== expected) {
      return reply.code(401).send({
        error: 'unauthorized',
        message: 'Varuna requires Authorization: Bearer <VARUNA_API_TOKEN> on this route.',
        statusCode: 401,
      });
    }
  };
}
