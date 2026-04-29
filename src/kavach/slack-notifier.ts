// [EE] AEGIS — Slack notification channel
// Sends Block Kit messages for KAVACH DAN gate interceptions and budget alerts.
// Slack is read-only: responses must come via the primary channel (Telegram/WhatsApp).
// @rule:KAV-055 multi-channel delivery

import type { AlertEvent, KavachApproval, AegisConfig } from "../core/types";

const LEVEL_EMOJI: Record<number, string> = { 1: "⚠️", 2: "🔴", 3: "🚨", 4: "☠️" };

function slackCfg(config: AegisConfig) {
  return {
    enabled: config.kavach.slack_enabled ?? false,
    webhook_url: config.kavach.slack_webhook_url ?? null,
    channel: config.kavach.slack_channel ?? null,
    username: config.kavach.slack_username || "AEGIS",
    icon_emoji: config.kavach.slack_icon_emoji || ":shield:",
  };
}

async function post(webhook: string, body: object): Promise<void> {
  await fetch(webhook, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

// Send a budget/anomaly/heartbeat alert to Slack
export async function sendSlackAlert(config: AegisConfig, alert: AlertEvent): Promise<void> {
  const cfg = slackCfg(config);
  if (!cfg.enabled || !cfg.webhook_url) return;

  const emoji = alert.severity === "critical" ? "🚨" : alert.severity === "warning" ? "⚠️" : "ℹ️";

  await post(cfg.webhook_url, {
    username: cfg.username,
    icon_emoji: cfg.icon_emoji,
    ...(cfg.channel ? { channel: cfg.channel } : {}),
    blocks: [
      {
        type: "header",
        text: { type: "plain_text", text: `${emoji} AEGIS — ${alert.type.replace(/_/g, " ").toUpperCase()}` },
      },
      {
        type: "section",
        text: { type: "mrkdwn", text: alert.message },
        fields: [
          { type: "mrkdwn", text: `*Severity:*\n${alert.severity}` },
          ...(alert.session_id
            ? [{ type: "mrkdwn", text: `*Session:*\n\`${alert.session_id.slice(0, 8)}\`` }]
            : []),
        ],
      },
      {
        type: "context",
        elements: [{ type: "mrkdwn", text: `🕐 ${new Date(alert.timestamp).toLocaleString()}` }],
      },
    ],
  });
}

// Send a KAVACH DAN gate interception to Slack (informational — approval via primary channel)
export async function sendSlackKavach(config: AegisConfig, approval: KavachApproval): Promise<void> {
  const cfg = slackCfg(config);
  if (!cfg.enabled || !cfg.webhook_url) return;

  const emoji = LEVEL_EMOJI[approval.level] ?? "🔴";
  const levelLabel = `DAN-${approval.level}`;

  await post(cfg.webhook_url, {
    username: cfg.username,
    icon_emoji: cfg.icon_emoji,
    ...(cfg.channel ? { channel: cfg.channel } : {}),
    blocks: [
      {
        type: "header",
        text: { type: "plain_text", text: `${emoji} KAVACH — ${levelLabel} Gate Triggered` },
      },
      {
        type: "section",
        text: {
          type: "mrkdwn",
          text: `*Command intercepted:*\n\`\`\`${approval.command.slice(0, 300)}\`\`\``,
        },
      },
      {
        type: "section",
        text: { type: "mrkdwn", text: `*What will happen:*\n${approval.consequence}` },
      },
      {
        type: "section",
        fields: [
          { type: "mrkdwn", text: `*Action ID:*\n\`${approval.id}\`` },
          { type: "mrkdwn", text: `*Level:*\n${levelLabel}` },
          { type: "mrkdwn", text: `*Tool:*\n${approval.tool_name}` },
          { type: "mrkdwn", text: `*Session:*\n\`${approval.session_id.slice(0, 8)}\`` },
        ],
      },
      {
        type: "section",
        text: {
          type: "mrkdwn",
          text: [
            "*Respond via primary channel (Telegram/WhatsApp):*",
            `• \`ALLOW ${approval.id}\` — let it run`,
            `• \`STOP ${approval.id}\` — block it`,
            `• \`EXPLAIN ${approval.id}\` — more detail`,
          ].join("\n"),
        },
      },
      {
        type: "context",
        elements: [
          {
            type: "mrkdwn",
            text: `🕐 ${new Date(approval.created_at).toLocaleString()} · Slack is read-only for KAVACH. Respond via primary channel.`,
          },
        ],
      },
    ],
  });
}
