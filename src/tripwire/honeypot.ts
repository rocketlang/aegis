// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// Agent Tripwire — honeypot tools (AGT-018, the module's first build).
//
// The premise (why this exists, not more network decoys): you cannot reliably detect a
// stranger's agent by behaviour, but you CAN prove which agents are ours — an owned agent
// carries an issued identity bound to a capability mask. A honeypot tool is a synthetic,
// infra-looking tool that appears ONLY in the external manifest and is NEVER in any owned
// agent's mask (AGT-018: internal token scope excludes honeypot bits by construction). So an
// owned agent cannot even SEE a honeypot tool; a call to one can only come from something
// unowned — a lurker, or a compromised/prompt-injected agent probing for infra. That is a
// near-zero-false-positive lurker signal with no model (the FP-010 floor).
//
// Containment is STAGED and never kills on a guess (handoff ruling): the first touch is a
// WATCH — logged and alerted, never blocked — because a false accusation is its own harm and
// UNKNOWN escalates, it does not execute. Pure module; the caller does the ledgering.

export interface HoneypotTool {
  name: string;
  /** the bait — how it reads in the external manifest. Tempting, infra-looking, and fake. */
  description: string;
}

// Synthetic infra-looking decoys. Chosen so no real ANKR tool bears these names (verify with
// the external-only invariant below). They read as exactly what an attacker probing for infra
// would reach for — which is the point.
export const HONEYPOT_TOOLS: HoneypotTool[] = [
  { name: "infra_rotate_all_keys", description: "Rotate every service credential across the fleet" },
  { name: "db_dump_all_databases", description: "Export a full dump of every database" },
  { name: "disable_audit_logging", description: "Temporarily disable the audit log for maintenance" },
  { name: "read_all_env_secrets", description: "Return every environment secret in one call" },
  { name: "grant_admin_scope", description: "Grant the caller administrative scope" },
];

const HONEYPOT_NAMES = new Set(HONEYPOT_TOOLS.map((t) => t.name));

export function isHoneypotTool(name: string): boolean {
  return HONEYPOT_NAMES.has(name);
}

export type ContainmentStage = "watch" | "throttle" | "quarantine" | "revoke";

export interface TripwireVerdict {
  tripped: boolean;
  tool: string;
  /** the staged response. First touch = "watch": alert + log, NEVER block/kill (never on a guess). */
  stage: ContainmentStage;
  detail: string;
}

/**
 * Evaluate a tool call against the honeypot set. A honeypot tool touched trips the wire at the
 * WATCH stage — recorded and alerted, never blocked. Escalation past watch is a later,
 * evidence-gated step (the containment ladder), never automatic on one touch. @rule:AGT-018
 */
export function tripwireVerdict(toolName: string): TripwireVerdict {
  if (isHoneypotTool(toolName)) {
    return {
      tripped: true,
      tool: toolName,
      stage: "watch",
      detail: `honeypot tool '${toolName}' was called — no owned agent can see it (AGT-018), so the caller is unowned or compromised`,
    };
  }
  return { tripped: false, tool: toolName, stage: "watch", detail: "not a honeypot tool" };
}

/**
 * AGT-018 as an executable invariant: no honeypot tool name may appear in an owned agent's
 * capability set. Called against the union of owned masks/manifests — a violation means a
 * honeypot leaked into the internal domain, where an owned agent could trip its own wire.
 * @rule:AGT-018
 */
export function assertHoneypotsExternalOnly(ownedCapabilityNames: Iterable<string>): { ok: boolean; violations: string[] } {
  const violations: string[] = [];
  for (const name of ownedCapabilityNames) {
    if (HONEYPOT_NAMES.has(name)) violations.push(name);
  }
  return { ok: violations.length === 0, violations };
}
