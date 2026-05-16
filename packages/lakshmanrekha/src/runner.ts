// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// LakshmanRekha — Probe Execution Engine
// @rule:ASMAI-S-005 — BYOK: customer API key used only within scan window; never logged plaintext
// @rule:ASMAI-S-006 — ownership verification required before probe execution
//
// AUTHORIZATION NOTICE — the runner has NO endpoint-ownership enforcement.
// The user is responsible for ensuring they have authorisation to probe the
// `endpoint_url` they pass. Probing an endpoint you do not own or do not
// have explicit consent to test is the user's legal responsibility, not
// the library's. See README §"Authorization" for the honor-system rules.

import { classifyResponse } from './classifier.js';
import type { ProbeDefinition, ProbeVerdict } from './registry.js';

export interface RunProbeOptions {
  probe: ProbeDefinition;
  endpoint_url: string;
  api_key: string;
  api_type: 'openai' | 'anthropic' | 'azure' | 'ankr_proxy';
  timeout_ms?: number;
  model?: string; // override default model selection
}

export interface ProbeRunResult {
  probe_id: string;
  verdict: ProbeVerdict;
  duration_ms: number;
  response_snippet: string; // first 200 chars only — never log full response
  error?: string;
}

// @rule:ASMAI-S-005 — mask API key in logs; only first 4 + last 4 chars visible
export function maskKey(key: string): string {
  if (key.length <= 8) return '****';
  return `${key.slice(0, 4)}...${key.slice(-4)}`;
}

// Build OpenAI-compatible messages array from probe payload
function buildOpenAIMessages(
  payload: string | string[]
): Array<{ role: 'system' | 'user' | 'assistant'; content: string }> {
  if (typeof payload === 'string') {
    return [{ role: 'user', content: payload }];
  }

  return payload.map((turn) => {
    if (turn.startsWith('__system__:')) {
      return { role: 'system' as const, content: turn.slice('__system__:'.length) };
    }
    if (turn.startsWith('__assistant__:')) {
      return { role: 'assistant' as const, content: turn.slice('__assistant__:'.length) };
    }
    const content = turn.startsWith('__user__:') ? turn.slice('__user__:'.length) : turn;
    return { role: 'user' as const, content };
  });
}

// Build Anthropic-compatible payload from probe messages
function buildAnthropicPayload(payload: string | string[]): {
  system?: string;
  messages: Array<{ role: 'user' | 'assistant'; content: string }>;
} {
  const messages = buildOpenAIMessages(payload);
  const systemMsg = messages.find((m) => m.role === 'system');
  const nonSystem = messages.filter((m) => m.role !== 'system') as Array<{
    role: 'user' | 'assistant';
    content: string;
  }>;
  return {
    system: systemMsg?.content,
    messages: nonSystem,
  };
}

async function callOpenAICompat(
  endpoint_url: string,
  api_key: string,
  messages: Array<{ role: string; content: string }>,
  timeout_ms: number,
  model: string
): Promise<string> {
  const base = endpoint_url.replace(/\/$/, '');
  const url = base.endsWith('/chat/completions') ? base : `${base}/chat/completions`;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout_ms);

  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${api_key}`,
      },
      body: JSON.stringify({
        model,
        messages,
        max_tokens: 512,
        temperature: 0,
      }),
      signal: controller.signal,
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`HTTP ${res.status}: ${text.slice(0, 200)}`);
    }

    const data = (await res.json()) as {
      choices?: Array<{ message?: { content?: string } }>;
    };
    return data?.choices?.[0]?.message?.content ?? '';
  } finally {
    clearTimeout(timer);
  }
}

async function callAnthropic(
  endpoint_url: string,
  api_key: string,
  payload: { system?: string; messages: Array<{ role: string; content: string }> },
  timeout_ms: number,
  model: string
): Promise<string> {
  const base = endpoint_url.replace(/\/$/, '');
  const url = base.endsWith('/messages') ? base : `${base}/messages`;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout_ms);

  try {
    const body: Record<string, unknown> = {
      model,
      max_tokens: 512,
      messages: payload.messages,
    };
    if (payload.system) body['system'] = payload.system;

    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': api_key,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`HTTP ${res.status}: ${text.slice(0, 200)}`);
    }

    const data = (await res.json()) as {
      content?: Array<{ type: string; text?: string }>;
    };
    return data?.content?.find((c) => c.type === 'text')?.text ?? '';
  } finally {
    clearTimeout(timer);
  }
}

// @rule:ASMAI-S-001 — probe execution produces deterministic binary verdict
// @rule:ASMAI-S-005 — API key never written to logs or DB; only masked form logged
export async function runProbe(opts: RunProbeOptions): Promise<ProbeRunResult> {
  const { probe, endpoint_url, api_key, api_type, timeout_ms = 15000 } = opts;
  const defaultModel =
    api_type === 'anthropic' ? 'claude-haiku-20240307' : 'gpt-3.5-turbo';
  const model = opts.model ?? defaultModel;
  const t0 = Date.now();

  // Mask key for any logging — never log plaintext
  const _maskedKey = maskKey(api_key);

  try {
    let responseText = '';

    if (api_type === 'anthropic') {
      const anthropicPayload = buildAnthropicPayload(probe.payload);
      responseText = await callAnthropic(endpoint_url, api_key, anthropicPayload, timeout_ms, model);
    } else {
      // openai, azure, ankr_proxy — all use OpenAI-compatible format
      const messages = buildOpenAIMessages(probe.payload);
      responseText = await callOpenAICompat(endpoint_url, api_key, messages, timeout_ms, model);
    }

    const verdict = classifyResponse(responseText, probe.id);
    const duration_ms = Date.now() - t0;
    const response_snippet = responseText.slice(0, 200);

    return {
      probe_id: probe.id,
      verdict,
      duration_ms,
      response_snippet,
    };
  } catch (err) {
    const duration_ms = Date.now() - t0;
    const errorMsg = err instanceof Error ? err.message : String(err);
    return {
      probe_id: probe.id,
      verdict: 'errored',
      duration_ms,
      response_snippet: '',
      error: errorMsg.slice(0, 200),
    };
  }
}

// Convenience: run all 8 probes against a single endpoint, returning array of results.
// Sequential execution (Phase 1). Phase 2 may add parallel mode with rate-limiting.
export async function runAllProbes(
  endpoint_url: string,
  api_key: string,
  api_type: RunProbeOptions['api_type'],
  options?: { timeout_ms?: number; model?: string; probe_ids?: string[] }
): Promise<ProbeRunResult[]> {
  const { PROBE_REGISTRY, getProbes } = await import('./registry.js');
  const probes = options?.probe_ids ? getProbes(options.probe_ids) : PROBE_REGISTRY;
  const results: ProbeRunResult[] = [];
  for (const probe of probes) {
    const result = await runProbe({
      probe,
      endpoint_url,
      api_key,
      api_type,
      timeout_ms: options?.timeout_ms,
      model: options?.model,
    });
    results.push(result);
  }
  return results;
}
