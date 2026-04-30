// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// @rule:KOS-025 Kernel anomaly notification — 4-tier escalation via webhook (opt-in)
// @rule:KOS-026 Silence = STOP (matches KAV-056 — no unsafe default)
// @rule:KOS-027 Two-layer message: plain English + technical detail (internal + external use)

import { loadConfig } from "../core/config";
import { createKavachApproval, getKavachApproval } from "../core/db";
import { randomBytes } from "crypto";

// ── Escalation tiers ──────────────────────────────────────────────────────────

export type KernelNotifyTier =
  | 1  // auto-approve + silent log
  | 2  // FYI Telegram, no reply needed, agent doesn't wait
  | 3  // ALLOW/STOP required — agent waits (Falco CRITICAL, valve CRACKED)
  | 4; // auto-block, FYI Telegram only (valve LOCKED, clearly malicious)

// Tier 3 only — other tiers fire-and-forget or silent
export type KernelDecision = "ALLOW" | "STOP";

export interface KernelNotifyEvent {
  tier: KernelNotifyTier;
  session_id: string;
  agent_id: string | null;
  domain: string;
  // What triggered this
  trigger: "falco_critical" | "valve_cracked" | "valve_locked" | "rate_exceeded" | "supervisor_ambiguous" | "profile_drift";
  // Plain English (external-facing)
  plain_summary: string;
  // Technical detail (operator-facing)
  technical_detail: string;
  falco_rule?: string;
  syscall?: string;
  severity?: string;
  trust_mask?: number;
  profile_hash?: string;
}

// ── Syscall translator — syscall name → plain English ────────────────────────
// @rule:KOS-027 operators without Linux knowledge can still act on the alert

const SYSCALL_PLAIN: Record<string, string> = {
  execve: "execute a program or shell command",
  execveat: "execute a program from a file descriptor",
  clone: "create a child process",
  clone3: "create a child process (modern)",
  fork: "duplicate the current process",
  "socket": "open a network socket",
  "connect": "connect to a remote server",
  "bind": "listen on a network port",
  "sendto": "send data over the network",
  "recvfrom": "receive data from the network",
  "open": "open a file",
  "openat": "open a file (relative path)",
  "unlink": "delete a file",
  "unlinkat": "delete a file (relative path)",
  "rename": "rename or move a file",
  "chmod": "change file permissions",
  "chown": "change file ownership",
  "ptrace": "attach to and control another process",
  "mmap": "map memory (large allocation)",
  "memfd_create": "create an anonymous memory region",
  "inotify_init1": "watch a directory for file changes",
  "keyctl": "access cryptographic keys",
  "sethostname": "change the system hostname",
  "prctl": "change process control settings",
  "kill": "send a signal to another process",
  "tgkill": "send a signal to a specific thread",
  "seccomp": "modify syscall filtering (privilege escalation attempt)",
  "mount": "mount a filesystem",
  "umount2": "unmount a filesystem",
  "chroot": "change the root directory",
  "pivot_root": "change the root filesystem",
  "setuid": "change user identity",
  "setgid": "change group identity",
  "capset": "modify Linux capabilities",
};

export function syscallToPlain(syscall: string): string {
  return SYSCALL_PLAIN[syscall] ?? `call syscall "${syscall}"`;
}

// ── Message builder (@rule:KOS-027 — two-layer) ───────────────────────────────

const TIER_EMOJI: Record<KernelNotifyTier, string> = {
  1: "ℹ️", 2: "🟡", 3: "🔴", 4: "🛑",
};

const TRIGGER_LABEL: Record<KernelNotifyEvent["trigger"], string> = {
  falco_critical:       "Falco CRITICAL — suspicious kernel event",
  valve_cracked:        "Gate valve → CRACKED (3+ violations)",
  valve_locked:         "Gate valve → LOCKED (agent fully stopped)",
  rate_exceeded:        "Violation rate exceeded (5+/min — possible exfil)",
  supervisor_ambiguous: "Supervisor cannot auto-decide",
  profile_drift:        "Seccomp profile tampering detected",
};

function buildMessage(event: KernelNotifyEvent, approvalId: string | null): string {
  const emoji = TIER_EMOJI[event.tier];
  const tierLabel = event.tier === 3 ? "Action Required" : event.tier === 4 ? "Auto-Blocked" : "Advisory";
  const lines: string[] = [
    `${emoji} KavachOS — ${tierLabel}`,
    ``,
    `Agent: ${event.agent_id ?? "unknown"}  |  Domain: ${event.domain}`,
    `Session: ${event.session_id}`,
    ``,
    `What happened:`,
    event.plain_summary,
    ``,
    `Technical detail:`,
    event.technical_detail,
  ];

  if (event.falco_rule) {
    lines.push(`Falco rule: "${event.falco_rule}"`);
  }
  if (event.trust_mask !== undefined) {
    lines.push(`Trust mask: 0x${event.trust_mask.toString(16).padStart(8, "0")}`);
  }
  if (event.profile_hash) {
    lines.push(`Profile: ${event.profile_hash.slice(0, 12)}...`);
  }

  lines.push(``);
  lines.push(`Trigger: ${TRIGGER_LABEL[event.trigger]}`);

  if (event.tier === 3 && approvalId) {
    lines.push(``);
    lines.push(`Reply with one word:`);
    lines.push(`  ALLOW ${approvalId} — permit, restore gate valve to OPEN`);
    lines.push(`  STOP ${approvalId}  — block, keep valve in current state`);
    lines.push(``);
    lines.push(`Expires: 10 min (silence = STOP)`);
  } else if (event.tier === 4) {
    lines.push(``);
    lines.push(`Agent is already blocked. No action needed.`);
    lines.push(`To release: kavachos valve release ${event.agent_id ?? event.session_id}`);
  } else if (event.tier === 2) {
    lines.push(``);
    lines.push(`No action needed — this is for your awareness.`);
    lines.push(`To review: kavachos profile show ${event.agent_id ?? event.session_id}`);
  }

  return lines.join("\n");
}

// ── Delivery via webhook (opt-in — only fires when webhook_url is configured) ──

async function sendViaWebhook(
  message: string,
  approvalId: string | null,
): Promise<boolean> {
  const config = loadConfig();
  const kc = config.kavach;
  if (!kc?.enabled) return false;

  const webhookUrl = kc.webhook_url || (kc as any).ankrclaw_url || "";
  if (!webhookUrl) return false;  // silent skip — notifications are opt-in

  const channel = kc.notify_channel || "telegram";
  const to = channel === "telegram" ? kc.notify_telegram_chat_id : kc.notify_phone;
  if (!to) return false;

  try {
    const res = await fetch(`${webhookUrl}/api/notify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        to,
        message,
        service: "KAVACHOS",
        channel,
        approval_id: approvalId ?? undefined,
      }),
    });
    return res.ok;
  } catch {
    process.stderr.write("[kavachos:notify] webhook unreachable — notification skipped\n");
    return false;
  }
}

// ── Poll for Tier 3 decision (@rule:KOS-026 — silence = STOP) ────────────────

async function pollForKernelDecision(
  approvalId: string,
  timeoutMs = 600_000,
): Promise<KernelDecision> {
  const deadline = Date.now() + timeoutMs;
  const POLL_INTERVAL = 2000;

  process.stderr.write(`[kavachos:notify] Waiting for kernel decision ${approvalId} (${Math.round(timeoutMs / 1000)}s timeout)\n`);

  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, POLL_INTERVAL));
    const approval = getKavachApproval(approvalId);
    if (!approval) continue;
    if (approval.status === "allowed") return "ALLOW";
    if (approval.status === "stopped" || approval.status === "timed_out") return "STOP";
  }

  // @rule:KOS-026 timeout = STOP — never ALLOW by silence
  process.stderr.write(`[kavachos:notify] Decision timeout for ${approvalId} → STOP\n`);
  return "STOP";
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Tier 2: fire-and-forget advisory. Agent does not wait.
 * @rule:KOS-025 Tier 2 — FYI, no block, no wait
 */
export async function notifyAdvisory(event: KernelNotifyEvent): Promise<void> {
  const message = buildMessage(event, null);
  process.stderr.write(`[kavachos:notify] ADVISORY: ${event.plain_summary}\n`);
  sendViaWebhook(message, null).catch(() => {});
}

/**
 * Tier 3: ALLOW/STOP required. Agent thread should wait on the returned decision.
 * @rule:KOS-025 Tier 3 — blocks caller until human decides or timeout
 * @rule:KOS-026 Silence = STOP
 */
export async function requestKernelApproval(event: KernelNotifyEvent): Promise<KernelDecision> {
  const approvalId = `KOS-${randomBytes(4).toString("hex").toUpperCase()}`;

  // Register in aegis.db so the webhook can route the reply
  createKavachApproval({
    id: approvalId,
    created_at: new Date().toISOString(),
    command: event.technical_detail,
    tool_name: `kavachos:${event.trigger}`,
    level: 3,
    consequence: event.plain_summary,
    session_id: event.session_id,
    timeout_ms: 600_000,
  });

  const message = buildMessage(event, approvalId);
  process.stderr.write(`[kavachos:notify] TIER-3 alert sent — ${approvalId}: ${event.plain_summary}\n`);

  await sendViaWebhook(message, approvalId);
  return pollForKernelDecision(approvalId);
}

/**
 * Tier 4: auto-blocked, notify only. No wait.
 * @rule:KOS-025 Tier 4 — block is already applied, inform human
 */
export async function notifyAutoBlock(event: KernelNotifyEvent): Promise<void> {
  const message = buildMessage(event, null);
  process.stderr.write(`[kavachos:notify] AUTO-BLOCK: ${event.plain_summary}\n`);
  sendViaWebhook(message, null).catch(() => {});
}
