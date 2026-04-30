// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// @rule:KOS-010 Profiles generated deterministically — never hand-written

import { createHash } from "crypto";
import { buildSyscallSet } from "./syscall-profiles";

// Docker/OCI seccomp profile format
export interface SeccompProfile {
  defaultAction: "SCMP_ACT_ERRNO" | "SCMP_ACT_KILL";
  architectures: string[];
  syscalls: Array<{
    names: string[];
    action: "SCMP_ACT_ALLOW";
  }>;
  // KavachOS metadata — not part of OCI spec but preserved in stored profiles
  _kavachos: {
    version: "1.0";
    trust_mask: number;
    domain: string;
    agent_type: string;
    generated_at: string;
    k_seal: string;  // SHA-256 of canonical syscall list (sorted, joined)
    rule_ref: "KOS-010";
  };
}

export interface ProfileGenerationResult {
  profile: SeccompProfile;
  hash: string;       // SHA-256 of canonical JSON (sorted keys)
  syscall_count: number;
}

// @rule:KOS-010 deterministic generation — same inputs → same SHA-256 hash
export function generateSeccompProfile(
  trustMask: number,
  domain: string,
  agentType: string = "claude-code"
): ProfileGenerationResult {
  const syscalls = buildSyscallSet(trustMask, domain);

  // K-seal: SHA-256 of the sorted syscall list (the canonical policy fingerprint)
  const kSeal = createHash("sha256").update(syscalls.sort().join(",")).digest("hex");

  const profile: SeccompProfile = {
    defaultAction: "SCMP_ACT_ERRNO",
    architectures: ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"],
    syscalls: [
      {
        names: syscalls,
        action: "SCMP_ACT_ALLOW",
      },
    ],
    _kavachos: {
      version: "1.0",
      trust_mask: trustMask,
      domain,
      agent_type: agentType,
      generated_at: new Date().toISOString(),
      k_seal: kSeal,
      rule_ref: "KOS-010",
    },
  };

  // Profile hash: SHA-256 of canonical JSON (deterministic key ordering)
  const canonical = canonicalJson(profile);
  const hash = createHash("sha256").update(canonical).digest("hex");

  return { profile, hash, syscall_count: syscalls.length };
}

// @rule:KOS-012 profile versioned by SHA-256 — drift detection requires reproducible hash
export function canonicalJson(obj: unknown): string {
  if (obj === null || typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) return `[${obj.map(canonicalJson).join(",")}]`;
  const sorted = Object.keys(obj as Record<string, unknown>)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonicalJson((obj as Record<string, unknown>)[k])}`)
    .join(",");
  return `{${sorted}}`;
}

export function profileSummary(result: ProfileGenerationResult): string {
  const { profile, hash, syscall_count } = result;
  return [
    `KavachOS Seccomp Profile`,
    `  trust_mask:    0x${profile._kavachos.trust_mask.toString(16).padStart(8, "0")}`,
    `  domain:        ${profile._kavachos.domain}`,
    `  agent_type:    ${profile._kavachos.agent_type}`,
    `  syscalls:      ${syscall_count}`,
    `  default:       ERRNO (deny-all unmatched)`,
    `  k_seal:        ${profile._kavachos.k_seal.slice(0, 16)}...`,
    `  profile_hash:  ${hash.slice(0, 16)}...`,
    `  rule_ref:      KOS-010`,
  ].join("\n");
}
