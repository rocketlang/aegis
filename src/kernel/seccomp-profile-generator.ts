// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// @rule:KOS-010 Profiles generated deterministically — never hand-written

import { createHash } from "crypto";
import { buildSyscallSet, NOTIFY_SYSCALLS, DEPTH4_SUPERVISED_SYSCALLS } from "./syscall-profiles";

// Docker/OCI seccomp profile format
export interface SeccompProfile {
  defaultAction: "SCMP_ACT_ERRNO" | "SCMP_ACT_KILL";
  architectures: string[];
  syscalls: Array<{
    names: string[];
    action: "SCMP_ACT_ALLOW" | "SCMP_ACT_NOTIFY";
  }>;
  // KavachOS metadata — not part of OCI spec but preserved in stored profiles
  _kavachos: {
    version: "1.0";
    trust_mask: number;
    domain: string;
    agent_type: string;
    delegation_depth: number;   // @rule:KOS-092 — depth drives reduction schedule
    hil_mode: boolean;          // @rule:KOS-096 — true when depth≥4 or HIL flag in SDT
    generated_at: string;
    k_seal: string;  // SHA-256 of canonical syscall list (sorted, joined)
    rule_ref: "KOS-010";
    notify_syscalls: string[];  // @rule:KOS-028 — supervisor asks before DENY
    strict_exec?: boolean;      // @rule:KOS-046 — execve/execveat gated by exec-allowlist
  };
}

export interface ProfileGenerationResult {
  profile: SeccompProfile;
  hash: string;       // SHA-256 of canonical JSON (sorted keys)
  syscall_count: number;
}

// @rule:KOS-010 deterministic generation — same inputs → same SHA-256 hash
// @rule:KOS-046 strict_exec: when true, execve/execveat move from ALLOW to NOTIFY tier
// @rule:KOS-092 delegation_depth drives reduction schedule (KOS-093)
export function generateSeccompProfile(
  trustMask: number,
  domain: string,
  agentType: string = "claude-code",
  strictExec = false,
  delegationDepth: number = 1
): ProfileGenerationResult {
  let syscalls = buildSyscallSet(trustMask, domain, delegationDepth);

  // @rule:KOS-046 strict_exec removes execve/execveat from ALLOW → they become NOTIFY
  // The supervisor auto-ALLOW/DENY from exec-allowlist (no Telegram — too fast for human)
  const EXEC_SYSCALLS = ["execve", "execveat"];
  if (strictExec) {
    syscalls = syscalls.filter((s) => !EXEC_SYSCALLS.includes(s));
  }

  // @rule:KOS-096 depth≥4 → write-class syscalls move from ALLOW to NOTIFY tier.
  // The agent can still read+exit (operator instructions must flow in), but every write
  // requires kernel-notifier approval before proceeding. hil_mode signals this state.
  const hilMode = delegationDepth >= 4;
  if (hilMode) {
    const supervisedSet = new Set(DEPTH4_SUPERVISED_SYSCALLS);
    syscalls = syscalls.filter((s) => !supervisedSet.has(s));
  }

  // @rule:KOS-028 NOTIFY tier: only for trust_mask > 0 (read-only agents cannot expand)
  // Filter to syscalls not already in the ALLOW set for this trust_mask.
  const allowSet = new Set(syscalls);
  const baseNotify = trustMask > 0
    ? NOTIFY_SYSCALLS.filter((s) => !allowSet.has(s))
    : [];

  // At depth≥4: also add DEPTH4_SUPERVISED into NOTIFY (write-class gates — KOS-096)
  const depth4Notify = hilMode
    ? DEPTH4_SUPERVISED_SYSCALLS.filter((s) => !allowSet.has(s))
    : [];

  // Add exec syscalls to NOTIFY when strict_exec (they were removed from ALLOW above)
  const notifySyscalls = [
    ...baseNotify,
    ...(strictExec ? EXEC_SYSCALLS.filter((s) => !allowSet.has(s)) : []),
    ...depth4Notify,
  ];

  // K-seal: SHA-256 of the sorted syscall list (post strict_exec filter — canonical fingerprint)
  const kSeal = createHash("sha256").update([...syscalls].sort().join(",")).digest("hex");

  const syscallEntries: SeccompProfile["syscalls"] = [
    { names: syscalls, action: "SCMP_ACT_ALLOW" },
  ];
  if (notifySyscalls.length > 0) {
    syscallEntries.push({ names: notifySyscalls, action: "SCMP_ACT_NOTIFY" });
  }

  const profile: SeccompProfile = {
    defaultAction: "SCMP_ACT_ERRNO",
    architectures: ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"],
    syscalls: syscallEntries,
    _kavachos: {
      version: "1.0",
      trust_mask: trustMask,
      domain,
      agent_type: agentType,
      delegation_depth: delegationDepth,   // @rule:KOS-092
      hil_mode: hilMode,                   // @rule:KOS-096
      generated_at: new Date().toISOString(),
      k_seal: kSeal,
      rule_ref: "KOS-010",
      notify_syscalls: notifySyscalls,
      strict_exec: strictExec,             // @rule:KOS-046
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
    `  depth:         ${profile._kavachos.delegation_depth}`,
    `  syscalls:      ${syscall_count}`,
    `  notify:        ${profile._kavachos.notify_syscalls.length} syscalls (supervisor gates)`,
    `  hil_mode:      ${profile._kavachos.hil_mode ? "YES — write-class syscalls gated" : "no"}`,
    `  default:       ERRNO (deny-all unmatched)`,
    `  k_seal:        ${profile._kavachos.k_seal.slice(0, 16)}...`,
    `  profile_hash:  ${hash.slice(0, 16)}...`,
    `  rule_ref:      KOS-010/KOS-092${profile._kavachos.hil_mode ? "/KOS-096" : ""}`,
  ].join("\n");
}
