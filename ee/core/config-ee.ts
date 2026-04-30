// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See ee/LICENSE-EE for terms.

// KOS-T102: EE config field defaults — dual_control + Slack
// These supplement the OSS AegisConfig when EE is licensed.
// OSS config.ts does not include these defaults.

export const EE_KAVACH_DEFAULTS = {
  dual_control_enabled: false,
  dual_control_second_chat_id: "",
  dual_control_second_channel: "telegram" as const,
  dual_control_require_different_approvers: false,
  slack_enabled: false,
  slack_webhook_url: process.env.KAVACH_SLACK_WEBHOOK_URL || null,
  slack_channel: process.env.KAVACH_SLACK_CHANNEL || null,
  slack_username: "AEGIS",
  slack_icon_emoji: ":shield:",
};
