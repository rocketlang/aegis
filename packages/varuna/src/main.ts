/**
 * Varuna — Maritime OT Posture
 *
 * Port: 4254 (from PORT env — never hardcoded per ankr-ctl policy)
 * Service key: xshieldai-varuna
 * Phase: 4 (OT pentest scope + testbed simulator + unified VAPT report)
 */

import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';
import Fastify from 'fastify';

import { registerAISRoutes } from './ais/routes.js';
import { registerCrewRoutes } from './crew/routes.js';
import { registerEdgeRoutes } from './edge/routes.js';
import { registerEvidenceRoutes } from './evidence/routes.js';
import { registerFactorRoutes } from './factors/routes.js';
import { registerForjaRoutes } from './forja/routes.js';
import { registerIACSRoutes } from './iacs/routes.js';
import { registerModbusRoutes } from './modbus/routes.js';
import { startBackgroundMonitor } from './monitor/background.js';
import { registerNMEARoutes } from './nmea/routes.js';
import { registerPentestRoutes } from './pentest/routes.js';
import { registerPostureRoutes } from './posture/routes.js';
import { registerProtocolRoutes } from './protocol/routes.js';
import { registerReportRoutes } from './report/routes.js';
import { registerTAXIIRoutes } from './taxii/routes.js';
import { registerTopologyRoutes } from './topology/routes.js';
import { resolveHost, resolveCorsOrigin, resolveAuth, makeAuthHook } from './security.js';

// ─── Port guard ───────────────────────────────────────────────────────────────
const PORT = process.env['PORT'];
if (!PORT) throw new Error('[xshieldai-varuna] PORT env not injected — use ankr-ctl to start');

// ─── Listener security — safe by default (see security.ts) ─────────────────────
const HOST = resolveHost(process.env);
const auth = resolveAuth(process.env, HOST);
if (auth.mode === 'refuse') {
  // Fail LOUD: never start an off-box, unauthenticated ingest listener.
  throw new Error(`[xshieldai-varuna] refusing to start — ${auth.reason}`);
}

// ─── Server ───────────────────────────────────────────────────────────────────
const app = Fastify({
  logger: {
    level: process.env['LOG_LEVEL'] ?? 'info',
    transport:
      process.env['NODE_ENV'] !== 'production'
        ? { target: 'pino-pretty', options: { colorize: true } }
        : undefined,
  },
});

await app.register(cors, {
  origin: resolveCorsOrigin(process.env), // OFF by default; set CORS_ORIGIN to open it
  methods: ['GET', 'POST', 'OPTIONS'],
});

// @rule:VRN-006 — ingest is a writer; every route but /health requires a bearer token when one is
// configured. With no token the server only reached here by being loopback-bound or explicitly
// opened (resolveAuth), so there is nothing to enforce; it warns instead of waving a public writer through.
if (auth.mode === 'token') {
  app.addHook('onRequest', makeAuthHook(auth.token!));
} else {
  app.log.warn(
    `[xshieldai-varuna] running WITHOUT API auth (${auth.reason ?? 'loopback-bound, local-dev convenience'}). ` +
    `Set VARUNA_API_TOKEN to require a bearer token.`,
  );
}

// @rule:VRN-006 Least-privilege applies to API surface too — tight rate limit
await app.register(rateLimit, {
  global: true,
  max: 60,
  timeWindow: '1 minute',
  keyGenerator: (req) => req.ip ?? 'unknown',
  errorResponseBuilder: (_req, context) => ({
    error: 'rate_limit_exceeded',
    message: `Limit: ${context.max} per ${context.after}. Retry after ${context.after}.`,
    statusCode: 429,
  }),
});

// ─── Health ───────────────────────────────────────────────────────────────────
app.get('/health', async () => ({
  status: 'ok',
  service: 'xshieldai-varuna',
  version: '0.1.0',
  port: PORT,
  phase: 'phase-4-pentest-vapt',
  timestamp: new Date().toISOString(),
}));

// ─── Routes ───────────────────────────────────────────────────────────────────
await registerForjaRoutes(app);
await registerEdgeRoutes(app);
await registerModbusRoutes(app);
await registerNMEARoutes(app);
await registerAISRoutes(app);
await registerTopologyRoutes(app);
await registerPostureRoutes(app);
await registerIACSRoutes(app);
await registerProtocolRoutes(app);
await registerEvidenceRoutes(app);
await registerReportRoutes(app);
await registerCrewRoutes(app);
await registerTAXIIRoutes(app);
await registerPentestRoutes(app);
await registerFactorRoutes(app);

// ─── Background monitor (hook must be before listen) ─────────────────────────
let monitorHandle: ReturnType<typeof setInterval> | undefined;
app.addHook('onClose', async () => {
  if (monitorHandle) {
    clearInterval(monitorHandle);
    app.log.info('[monitor] Background monitor stopped');
  }
});

// ─── Start ────────────────────────────────────────────────────────────────────
try {
  await app.listen({ port: parseInt(PORT), host: HOST });
  app.log.info(`Varuna Maritime OT Posture running on port ${PORT} (Phase 4 — Pentest/VAPT)`);

  // @rule:P3-003 Start background posture degradation monitor after listen
  monitorHandle = startBackgroundMonitor(app.log);
} catch (err) {
  app.log.error(err);
  process.exit(1);
}
