// SPDX-License-Identifier: AGPL-3.0-only
// AEGIS Dashboard — the adapters' token for the gate audit.
//
// Through 2.18.x GET /api/v1/kavach/audit answered anyone: it returns the text of every command that
// reached the gate, and it stayed open even on a dashboard exposed with a password set. The adapters
// (n8n, LangChain) have always been able to send `Authorization: Bearer <token>`; nothing here read it.
//
// From 2.19.0, on a dashboard with a password set, the audit needs a login session or this token:
// `dashboard.auth.api_token` in ~/.aegis/config.json. It opens the audit route and nothing else.
import { timingSafeEqual } from "crypto";

/** Shorter than this is not accepted as a token at all: it would be guessable. */
export const API_TOKEN_MIN = 24;

export const apiTokenUsable = (configured: unknown): configured is string =>
  typeof configured === "string" && configured.length >= API_TOKEN_MIN && !/\s/.test(configured);

/** True only for `Authorization: Bearer <the configured token>`, compared in constant time. */
export function apiTokenMatches(authorization: string | undefined, configured: unknown): boolean {
  if (!apiTokenUsable(configured) || typeof authorization !== "string") return false;
  if (!authorization.startsWith("Bearer ")) return false;
  const given = Buffer.from(authorization.slice(7), "utf8"), want = Buffer.from(configured, "utf8");
  return given.length === want.length && timingSafeEqual(given, want);
}

/** The one route the token opens. */
export const API_TOKEN_ROUTE = "/api/v1/kavach/audit";
