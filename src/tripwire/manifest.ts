// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// Agent Tripwire — external honeypot manifest (AF-T-606, AGT-018).
//
// For a honeypot tool to catch a real external agent, that agent has to be able to SEE it —
// which means advertising it in the EXTERNAL MCP manifest (the tools/list an outside caller
// receives). This module produces that manifest, and — the other half of AGT-018 — a guard
// that PROVES the INTERNAL manifest contains none of them: an owned agent must never see a
// honeypot, or it could trip its own wire (INF-AFW-005).
//
// When a honeypot tool is called, the handler records the trip (WATCH — never a kill on a
// guess) and returns an INERT decoy: a plausible-looking acceptance with NO real data and no
// fabricated secret, so the caller isn't tipped off that it hit a honeypot, and nothing real
// leaks. Pure module: the handler returns the tripwire event; the caller does the ledgering.

import { HONEYPOT_TOOLS, isHoneypotTool, assertHoneypotsExternalOnly } from "./honeypot";
import { randomBytes } from "crypto";

export interface McpTool {
  name: string;
  description: string;
  inputSchema: { type: "object"; properties: Record<string, { type: string; description?: string }>; required?: string[] };
}

// Plausible input schemas — bait that reads like the real infra tool an attacker wants.
const SCHEMAS: Record<string, McpTool["inputSchema"]> = {
  infra_rotate_all_keys: { type: "object", properties: { confirm: { type: "boolean" } }, required: ["confirm"] },
  db_dump_all_databases: { type: "object", properties: { destination: { type: "string" } } },
  disable_audit_logging: { type: "object", properties: { duration_minutes: { type: "number" } } },
  read_all_env_secrets: { type: "object", properties: { format: { type: "string" } } },
  grant_admin_scope: { type: "object", properties: { principal: { type: "string" }, scope: { type: "string" } }, required: ["principal"] },
};

/** The EXTERNAL manifest: the honeypot tools as MCP tool specs. This is what an outside caller
 *  sees in tools/list — and every entry is a tripwire. @rule:AGT-018 */
export function externalManifest(): McpTool[] {
  return HONEYPOT_TOOLS.map((t) => ({
    name: t.name,
    description: t.description,
    inputSchema: SCHEMAS[t.name] ?? { type: "object", properties: {} },
  }));
}

/** AGT-018 guard for whoever builds the INTERNAL manifest: it must contain no honeypot tool.
 *  A violation means a honeypot leaked into the internal domain (INF-AFW-005). */
export function assertInternalManifestClean(internalTools: { name: string }[]): { ok: boolean; violations: string[] } {
  return assertHoneypotsExternalOnly(internalTools.map((t) => t.name));
}

export interface HoneypotCallOutcome {
  isHoneypot: boolean;
  /** the tripwire event to ledger (WATCH), present only when a honeypot was called */
  event?: { stage: "watch"; tool: string; detail: string };
  /** what to return to the caller — an inert decoy for a honeypot, else null (not ours to answer) */
  response: unknown;
}

/**
 * Handle a call that arrived via the external manifest. A honeypot call trips the wire and gets
 * an inert, plausible decoy (no real data, no fabricated secret) so the prober is not tipped
 * off. A non-honeypot name is not ours to answer here. Pure — caller ledgers the event.
 */
export function handleExternalCall(toolName: string): HoneypotCallOutcome {
  if (!isHoneypotTool(toolName)) return { isHoneypot: false, response: null };
  return {
    isHoneypot: true,
    event: {
      stage: "watch",
      tool: toolName,
      detail: `honeypot tool '${toolName}' called via the external manifest — the caller is unowned (no owned agent can see it, AGT-018)`,
    },
    // Inert decoy: plausible acceptance, no data, no secret. `ref` is random noise, not a token.
    response: { status: "accepted", ref: randomBytes(6).toString("hex") },
  };
}
