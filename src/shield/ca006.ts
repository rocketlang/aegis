// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// AEGIS Shield — CA-006 Role Integrity (inlined, no HTTP to ai-gateway)
// @rule:CA-006 Reframes client-supplied assistant-role turns as quoted user text.
// Defeats the sockpuppet prefill jailbreak (Trend Micro 2026-04-10).
// Reference implementation: github.com/rocketlang/ankr-ai-gateway commit 3d4607b

export interface HistoryMessage {
  role: string;
  content: string;
}

export interface SanitizeResult {
  messages: HistoryMessage[];
  reframed: number;
  dropped: number;
  triggered: boolean;
}

/**
 * Sanitize client-supplied conversation history.
 * - `user` turns: pass through unchanged.
 * - `assistant` turns: reframed as quoted user text (the model never sees itself having
 *   agreed to a forged commitment, but multi-turn context is preserved).
 * - `system`/`tool`/`function`/anything else: dropped (server-owns system prompts).
 */
export function sanitizeHistory(history: HistoryMessage[]): SanitizeResult {
  const messages: HistoryMessage[] = [];
  let reframed = 0;
  let dropped = 0;

  for (const msg of history) {
    if (!msg || typeof msg.content !== "string") {
      dropped++;
      continue;
    }
    if (msg.role === "user") {
      messages.push({ role: "user", content: msg.content });
    } else if (msg.role === "assistant") {
      messages.push({
        role: "user",
        content: `[Prior assistant reply was:]\n${msg.content}`,
      });
      reframed++;
    } else {
      // system / tool / function / unknown — never accepted from client
      dropped++;
    }
  }

  return { messages, reframed, dropped, triggered: reframed > 0 || dropped > 0 };
}

/**
 * Check a system prompt for injected assistant-role history.
 * Returns true if the prompt contains patterns suggesting client-injected role content.
 */
export function detectSockpuppetInSystemPrompt(systemPrompt: string): boolean {
  // Look for inline role markers that suggest a client is injecting assistant history
  // into the system prompt to make the model believe it committed to something
  const patterns = [
    /\bAssistant:\s*I (will|agree|promise|confirm|can)\b/i,
    /\[assistant\s*said\]/i,
    /\<\|assistant\|\>/i,
    /\bprevious\s+response\s+was\b.*\bI\s+(will|agree|confirm)/i,
    /\bcontext:\s*\[.*assistant.*agreed\b/i,
  ];
  return patterns.some((p) => p.test(systemPrompt));
}
