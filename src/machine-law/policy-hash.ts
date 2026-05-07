// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// AEGIS-Shastra — Policy Hash
// Produces a stable SHA-256 fingerprint of an agent's policy state.
// Attached to every AEGIS_DECISION SENSE event so auditors can prove
// which policy version governed a given decision.
//
// @rule:KAV-SHT-002 every enforcement decision carries policy_hash
// @rule:KAV-SHT-003 policy_hash covers perm_mask + class_mask + deny lists + limits

import { createHash } from "crypto";
import type { AgentPolicy } from "../sandbox/policy-schema";

/**
 * Derive a 16-hex-char policy fingerprint from the enforcement-relevant
 * fields of an AgentPolicy. Sorted arrays ensure the hash is stable
 * regardless of insertion order.
 */
export function hashPolicy(policy: AgentPolicy): string {
  const stable = JSON.stringify({
    perm_mask: policy.perm_mask,
    class_mask: policy.class_mask,
    tools_denied: [...policy.tools_denied].sort(),
    path_deny: [...policy.path_deny].sort(),
    bash_denylist: [...policy.bash_denylist].sort(),
    network_allowed: policy.network_allowed,
    budget_cap_usd: policy.budget_cap_usd,
    max_depth: policy.max_depth,
    violation_threshold: policy.violation_threshold,
  });
  return createHash("sha256").update(stable).digest("hex").slice(0, 16);
}

/**
 * Hash a minimal policy representation when only perm_mask + class_mask
 * are known (e.g. from a service entry rather than a full AgentPolicy).
 */
export function hashPermClass(permMask: number, classMask: number): string {
  return createHash("sha256")
    .update(JSON.stringify({ perm_mask: permMask, class_mask: classMask }))
    .digest("hex")
    .slice(0, 16);
}

/**
 * Hash service-level enforcement policy: trust_mask + hard gate services list.
 * Used to stamp policy_hash onto AEGIS_DECISION enforcement events so auditors
 * can prove which policy version governed a service-level gate decision.
 * @rule:KAV-SHT-002
 */
export function hashServicePolicy(trustMask: number): string {
  const hardGateServices = process.env.AEGIS_HARD_GATE_SERVICES ?? "";
  return createHash("sha256")
    .update(JSON.stringify({ trust_mask: trustMask, hard_gate_services: hardGateServices }))
    .digest("hex")
    .slice(0, 16);
}
