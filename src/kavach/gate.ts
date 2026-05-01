// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// KAVACH Gate — Dangerous Action Notification + Human Approval
// @rule:KAV-052 Pre-execution intercept for destructive actions
// @rule:KAV-053 Blast radius assessment ≤ 3 seconds
// @rule:KAV-054 Plain-English renderer, three-word response format
// @rule:KAV-055 Multi-channel delivery (Telegram + WhatsApp + webhook)
// @rule:KAV-056 Default-safe timeout — silence = BLOCK
// @rule:KAV-059 Audit record for every interception

import { randomBytes } from "crypto";
import { loadConfig, DASHBOARD_PORT } from "../core/config";
import {
  createKavachApproval, getKavachApproval, decideKavachApproval,
  markKavachNotified, addAlert, getPendingApprovals,
} from "../core/db";
import type { KavachLevel, KavachDecision, KavachApproval } from "../core/types";
// [EE] Slack gate notification — no-op when EE not licensed
type _SendSlackKavachFn = (config: ReturnType<typeof loadConfig>, approval: KavachApproval) => Promise<void>;
let _sendSlackKavach: _SendSlackKavachFn | null = null;
try { _sendSlackKavach = (require("../../ee/kavach/slack-notifier") as any).sendSlackKavach; } catch {}
function sendSlackKavach(config: ReturnType<typeof loadConfig>, approval: KavachApproval): Promise<void> {
  return _sendSlackKavach?.(config, approval) ?? Promise.resolve();
}

// --- DAN Level classification (@rule:KAV-052) ---

interface LevelRule {
  pattern: RegExp;
  level: KavachLevel;
  consequence: (cmd: string) => string;
}

const LEVEL_RULES: LevelRule[] = [
  // DAN-4 — irreversible + catastrophic blast
  {
    pattern: /prisma\s+migrate\s+reset|DROP\s+DATABASE|dropdb\s|pg_dropcluster|rm\s+-rf\s+\/(?:root|home|var|etc|usr)\b/i,
    level: 4,
    consequence: (cmd) =>
      `This will permanently destroy an entire database or critical system directory. All data will be unrecoverable. Blast radius: CRITICAL — multiple services will fail.`,
  },
  // DAN-3 — irreversible, significant blast
  {
    pattern: /prisma\s+db\s+push.*--force-reset|DROP\s+SCHEMA|TRUNCATE.*CASCADE|docker\s+compose\s+down\s+-v|rm\s+-rf\s+\S+\/(data|backups?|postgres|db)\b|git\s+push.*--force.*(?:main|master|prod)/i,
    level: 3,
    consequence: (cmd) =>
      cmd.includes("prisma") || cmd.includes("DROP") || cmd.includes("TRUNCATE")
        ? `This will drop all tables and schema data. Existing records will be permanently deleted. Recovery requires a backup restore.`
        : cmd.includes("docker")
        ? `This will destroy Docker volumes — all persistent data stored in containers will be permanently deleted.`
        : cmd.includes("git")
        ? `This will overwrite the protected branch history. Commits may be permanently lost for all collaborators.`
        : `This is an irreversible destructive action affecting production data or infrastructure.`,
  },
  // DAN-2 — hard to recover, targeted destruction
  {
    pattern: /DROP\s+TABLE|TRUNCATE\s+TABLE|DELETE\s+FROM.*(?:WHERE\s+1|WITHOUT\s+WHERE)|prisma\s+db\s+push|rm\s+-rf\s+\S+|ALTER\s+TABLE.*DROP\s+COLUMN/i,
    level: 2,
    consequence: (cmd) =>
      cmd.match(/DROP\s+TABLE/i)
        ? `This will permanently delete a database table and all its data.`
        : cmd.match(/TRUNCATE/i)
        ? `This will delete all rows in a table instantly. The table structure stays but all data is gone.`
        : cmd.match(/DELETE\s+FROM/i)
        ? `This will delete all rows matching the condition. Large deletes may not be easily reversible.`
        : cmd.match(/prisma\s+db\s+push/i)
        ? `Prisma db push may run destructive schema migrations on a live database without a migration history trail.`
        : cmd.match(/rm\s+-rf/i)
        ? `This will recursively delete files and directories. Deleted files cannot be recovered without a backup.`
        : `This action will cause data loss that is difficult to reverse.`,
  },
  // DAN-1 — recoverable with effort
  {
    pattern: /DELETE\s+FROM|UPDATE\s+.*SET\s+.*WHERE|prisma\s+migrate\s+dev|git\s+reset\s+--hard|git\s+clean\s+-fd/i,
    level: 1,
    consequence: (cmd) =>
      cmd.match(/DELETE\s+FROM/i)
        ? `This will delete rows matching the WHERE condition. Recoverable from backup if taken recently.`
        : cmd.match(/UPDATE\s+.*SET/i)
        ? `This will update rows in the database. Recoverable from backup but may require manual effort.`
        : `This action may cause data loss that is recoverable with effort from a recent backup.`,
  },
];

export function classifyCommand(command: string): { level: KavachLevel; consequence: string } | null {
  for (const rule of LEVEL_RULES) {
    if (rule.pattern.test(command)) {
      return { level: rule.level, consequence: rule.consequence(command) };
    }
  }
  return null;
}

// --- Gate entry point (@rule:KAV-052) ---

export interface GateResult {
  decision: KavachDecision;
  approval_id: string;
  level: KavachLevel;
  message: string;
}

export async function runKavachGate(
  command: string,
  toolName: string,
  sessionId: string
): Promise<GateResult> {
  const config = loadConfig();
  const classification = classifyCommand(command);

  if (!classification) {
    return { decision: "ALLOW", approval_id: "", level: 1, message: "no dangerous patterns found" };
  }

  const { level, consequence } = classification;

  // @rule:KAV-056 — timeout per level
  const timeoutMap: Record<KavachLevel, number> = {
    1: (config.kavach?.timeout_level1_s ?? 600) * 1000,
    2: (config.kavach?.timeout_level2_s ?? 300) * 1000,
    3: (config.kavach?.timeout_level3_s ?? 120) * 1000,
    4: (config.kavach?.timeout_level4_s ?? 60) * 1000,
  };
  const timeoutMs = timeoutMap[level];

  const approvalId = `KAVACH-${randomBytes(4).toString("hex").toUpperCase()}`;

  // @rule:KAV-059 — create audit record before notification
  createKavachApproval({
    id: approvalId,
    created_at: new Date().toISOString(),
    command: command.slice(0, 2000),
    tool_name: toolName,
    level,
    consequence,
    session_id: sessionId,
    timeout_ms: timeoutMs,
  });

  // @rule:KAV-053 + KAV-054 — assess blast radius and render plain-English message
  const notificationText = buildNotificationMessage(approvalId, command, level, consequence, timeoutMs);

  // @rule:KAV-055 — notify via webhook (opt-in: Telegram primary, WhatsApp fallback)
  await sendKavachNotification(approvalId, notificationText, config);

  // [EE] Slack secondary notification
  const approval = getKavachApproval(approvalId);
  if (approval) sendSlackKavach(config, approval).catch(() => {});

  // Log as alert for dashboard visibility
  addAlert({
    type: "kill" as any,  // reuse 'kill' severity channel — displayed as critical in dashboard
    severity: "critical",
    message: `KAVACH L${level}: ${command.slice(0, 80)}`,
    session_id: sessionId,
    timestamp: new Date().toISOString(),
  });

  const dualControl = !!(config.kavach?.dual_control_enabled && level === 4);

  // @rule:KAV-056 — poll for decision, default-safe timeout = BLOCK
  // @rule:KAV-060 — L4 dual-control: wait for pending_second, then notify second approver
  const decision = await pollForDecision(approvalId, timeoutMs, dualControl, config);

  return { decision, approval_id: approvalId, level, message: consequence };
}

// --- Message renderer (@rule:KAV-054) ---

const LEVEL_LABELS: Record<KavachLevel, string> = {
  1: "L1 — Recoverable (backup needed)",
  2: "L2 — Hard to recover",
  3: "L3 — Irreversible",
  4: "L4 — Irreversible + High blast radius",
};

const LEVEL_EMOJI: Record<KavachLevel, string> = {
  1: "⚠️", 2: "🔴", 3: "🚨", 4: "🛑",
};

function buildNotificationMessage(
  approvalId: string,
  command: string,
  level: KavachLevel,
  consequence: string,
  timeoutMs: number
): string {
  const timeoutMin = Math.round(timeoutMs / 60000);
  const timeoutLabel = timeoutMin >= 1 ? `${timeoutMin} min` : `${timeoutMs / 1000}s`;
  const displayCmd = command.length > 120 ? command.slice(0, 120) + "…" : command;

  return [
    `${LEVEL_EMOJI[level]} KAVACH — Action Requires Approval`,
    ``,
    `Agent wants to run:`,
    `\`${displayCmd}\``,
    ``,
    `Consequence:`,
    consequence,
    ``,
    `Level: ${LEVEL_LABELS[level]}`,
    ``,
    `Reply with one word:`,
    `  STOP — block this action`,
    `  ALLOW — permit this action`,
    `  EXPLAIN — send full session context first`,
    ``,
    `Approval ID: ${approvalId}`,
    `Expires: ${timeoutLabel} (silence = STOP)`,
    `Dashboard: http://localhost:${DASHBOARD_PORT}`,
  ].join("\n");
}

// --- Notification delivery (@rule:KAV-055) ---

async function sendKavachNotification(
  approvalId: string,
  text: string,
  config: ReturnType<typeof loadConfig>,
  approver: "first" | "second" = "first"
): Promise<void> {
  const kc = config.kavach;
  if (!kc?.enabled) return;

  // Support legacy ankrclaw_url field name in existing configs
  const webhookUrl = kc.webhook_url || (kc as any).ankrclaw_url || "";
  if (!webhookUrl) return;  // silent skip — notifications are opt-in

  // Route to first or second approver channel
  const channel = approver === "second"
    ? (kc.dual_control_second_channel || kc.notify_channel || "telegram")
    : (kc.notify_channel || "telegram");

  const to = approver === "second"
    ? (kc.dual_control_second_chat_id || kc.notify_telegram_chat_id)
    : (channel === "telegram" ? kc.notify_telegram_chat_id : kc.notify_phone);

  if (!to) {
    process.stderr.write(
      approver === "second"
        ? `[KAVACH] No dual_control_second_chat_id set — second approval via dashboard only\n`
        : `[KAVACH] No notify_telegram_chat_id set — add chat_id to ~/.aegis/config.json\n`
    );
    return;
  }

  try {
    const res = await fetch(`${webhookUrl}/api/notify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ to, message: text, service: "KAVACH", channel }),
    });
    if (res.ok) {
      if (approver === "first") markKavachNotified(approvalId);
      const hint = channel === "telegram" ? `TG:${to}` : `WA:${to.slice(-4)}`;
      process.stderr.write(`[KAVACH] Notified ${approver} approver ${hint} — ${approvalId}\n`);
    }
  } catch {
    process.stderr.write(`[KAVACH] Notification webhook unreachable — decision via dashboard only\n`);
  }
}

// --- Decision polling (@rule:KAV-056 — silence = BLOCK, @rule:KAV-060 — dual-control) ---

async function pollForDecision(
  approvalId: string,
  timeoutMs: number,
  dualControl: boolean,
  config: ReturnType<typeof loadConfig>
): Promise<KavachDecision> {
  const deadline = Date.now() + timeoutMs;
  const POLL_INTERVAL = 2000;
  let secondNotified = false;

  process.stderr.write(`[KAVACH] Waiting for approval ${approvalId} (${Math.round(timeoutMs / 1000)}s timeout${dualControl ? ", dual-control L4" : ""})\n`);

  while (Date.now() < deadline) {
    await sleep(POLL_INTERVAL);
    const approval = getKavachApproval(approvalId);
    if (!approval) continue;

    // Terminal states
    if (approval.status === "allowed") return "ALLOW";
    if (approval.status === "explained") return "EXPLAIN";
    if (approval.status === "stopped" || approval.status === "timed_out") return "STOP";

    // @rule:KAV-060 — dual-control: first ALLOW received, notify second approver
    if (dualControl && approval.status === "pending_second" && !secondNotified) {
      secondNotified = true;
      process.stderr.write(`[KAVACH] First ALLOW received — notifying second approver\n`);
      const secondText = buildSecondApproverMessage(approvalId, approval.command, approval.consequence, approval.first_approver);
      await sendKavachNotification(approvalId, secondText, config, "second");
    }
  }

  // @rule:KAV-056 — timeout = BLOCK, never ALLOW
  decideKavachApproval(approvalId, "TIMEOUT", "system-timeout", {
    dual_control: dualControl,
    require_different_approvers: config.kavach?.dual_control_require_different_approvers ?? false,
  });
  process.stderr.write(`[KAVACH] Timeout — ${approvalId} blocked by default\n`);
  return "TIMEOUT";
}

function buildSecondApproverMessage(
  approvalId: string,
  command: string,
  consequence: string,
  firstApprover: string | null
): string {
  const displayCmd = command.length > 120 ? command.slice(0, 120) + "…" : command;
  return [
    `🛑 KAVACH — L4 Second Approval Required`,
    ``,
    `First approver: ${firstApprover ?? "unknown"} has ALLOWed.`,
    `Your approval is required to proceed.`,
    ``,
    `Command: \`${displayCmd}\``,
    `Consequence: ${consequence}`,
    ``,
    `Reply:`,
    `  ALLOW ${approvalId}`,
    `  STOP ${approvalId}`,
    ``,
    `Silence = STOP`,
  ].join("\n");
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
