// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// Token-to-USD conversion for major models
// Prices per million tokens (MTok) as of April 2026

interface ModelPricing {
  input: number;       // $/MTok
  output: number;      // $/MTok
  cache_read: number;  // $/MTok
  cache_write: number; // $/MTok
}

const PRICING: Record<string, ModelPricing> = {
  // Claude Opus 4.6
  "claude-opus-4-6": { input: 15, output: 75, cache_read: 1.875, cache_write: 18.75 },
  // Claude Sonnet 4.6
  "claude-sonnet-4-6": { input: 3, output: 15, cache_read: 0.375, cache_write: 3.75 },
  // Claude Haiku 4.5
  "claude-haiku-4-5-20251001": { input: 0.80, output: 4, cache_read: 0.08, cache_write: 1 },
  // Fallback / unknown models — use Opus pricing as conservative estimate
  "_default": { input: 15, output: 75, cache_read: 1.875, cache_write: 18.75 },
};

// Normalize model names — Claude Code sometimes sends abbreviated names
function resolveModel(model: string): string {
  if (!model) return "_default";
  const lower = model.toLowerCase();
  if (lower.includes("opus")) return "claude-opus-4-6";
  if (lower.includes("sonnet")) return "claude-sonnet-4-6";
  if (lower.includes("haiku")) return "claude-haiku-4-5-20251001";
  return PRICING[model] ? model : "_default";
}

export function estimateCostUsd(
  model: string,
  input_tokens: number,
  output_tokens: number,
  cache_read_tokens: number,
  cache_creation_tokens: number,
  pricing_mode: "api" | "max_plan" = "api",
  max_plan_discount: number = 0.2
): number {
  const resolved = resolveModel(model);
  const p = PRICING[resolved] || PRICING["_default"];

  const cost =
    (input_tokens / 1_000_000) * p.input +
    (output_tokens / 1_000_000) * p.output +
    (cache_read_tokens / 1_000_000) * p.cache_read +
    (cache_creation_tokens / 1_000_000) * p.cache_write;

  // Max Plan pricing is opaque. Apply discount factor as approximation.
  if (pricing_mode === "max_plan") {
    return cost * max_plan_discount;
  }

  return cost;
}

export function getModelPricing(model: string): ModelPricing {
  const resolved = resolveModel(model);
  return PRICING[resolved] || PRICING["_default"];
}
