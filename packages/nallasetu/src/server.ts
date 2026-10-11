// SPDX-License-Identifier: AGPL-3.0-only
// Nallasetu — Fastify server
// Port: 4898 (security.nallasetu in ports.json)
// @rule:NLS-016 500ms latency budget monitored at server level

import Fastify from "fastify";
import cors from "@fastify/cors";
import helmet from "@fastify/helmet";
import { registerHandshakeRoutes } from "./routes/handshake";
import { registerSessionRoutes } from "./routes/sessions";
import { registerForjaRoutes } from "./routes/forja";
import { ensureResponderKey } from "./handshake";
import { policyHash } from "./crypto";
import pkg from "../package.json";
import { resolveHost, resolveAuth, resolveCorsOrigin, isPublicRoute, tokenMatches } from "./security";

const PORT = parseInt(process.env.PORT ?? "4898", 10);
const RESPONDER_ID = process.env.NALLASETU_RESPONDER_ID ?? "nallasetu-v0";
// Who may reach the listener: closed by default since 0.4.0 (see security.ts).
const HOST = resolveHost(process.env);
const auth = resolveAuth(process.env, HOST);
if (auth.mode === "refuse") {
  console.error(`[nallasetu] REFUSING TO START: ${auth.reason}`);
  process.exit(1);
}

const app = Fastify({
  logger: {
    level: process.env.LOG_LEVEL ?? "info",
    serializers: {
      req: (req) => ({ method: req.method, url: req.url }),
    },
  },
  requestTimeout: 5000,
});

await app.register(cors, { origin: resolveCorsOrigin(process.env) }); // off unless NALLASETU_CORS_ORIGIN is set
await app.register(helmet, { contentSecurityPolicy: false });

if (auth.mode === "token") {
  const token = auth.token!;
  app.addHook("onRequest", async (req, reply) => {
    if (isPublicRoute(req.method, req.routeOptions?.url)) return;
    if (!tokenMatches(req.headers.authorization, token)) {
      return reply.code(401).send({ error: "unauthorized", message: "Nallasetu requires Authorization: Bearer <NALLASETU_API_TOKEN> on this route.", statusCode: 401 });
    }
  });
} else {
  app.log.warn(`[nallasetu] running WITHOUT authentication (${auth.reason}). Set NALLASETU_API_TOKEN to require a bearer token.`);
}

// @rule:NLS-016 latency budget logging
app.addHook("onResponse", (req, reply, done) => {
  const ms = Math.round(reply.elapsedTime);
  if (ms > 500) {
    app.log.warn({ url: req.url, latency_ms: ms }, "NLS-016 latency budget exceeded");
  }
  done();
});

// Health
app.get("/health", async (_req, reply) => {
  return reply.send({
    status: "ok",
    service: "nallasetu",
    version: pkg.version,
    responder_id: RESPONDER_ID,
    policy_hash: policyHash(),
    uptime_s: Math.round(process.uptime()),
  });
});

// Register all route groups
registerHandshakeRoutes(app);
registerSessionRoutes(app);
registerForjaRoutes(app);

// Bootstrap responder key (Customer Zero — self-registers if unknown)
const { keyId } = ensureResponderKey(RESPONDER_ID);
app.log.info({ responder_id: RESPONDER_ID, key_id: keyId }, "Nallasetu responder key ready");

try {
  await app.listen({ port: PORT, host: HOST });
  app.log.info(`Nallasetu listening on :${PORT} — policy_hash=${policyHash()}`);
} catch (err) {
  app.log.error(err);
  process.exit(1);
}
