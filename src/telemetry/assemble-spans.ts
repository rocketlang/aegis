// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// @rule:KOS-091 span assembly — TurnRow[] → OtelSpan[] for OTLP export
//
// Span tree per turn:
//   kavachos.agent.turn   (root, kind=SERVER)
//   ├── kavachos.tool.{name}  (child per tool call, kind=INTERNAL)
//   └── kavachos.llm.call     (child per LLM call, kind=CLIENT)

import type { TurnRow, ToolCallEntry, LlmCallEntry } from "./turn-store";
import { newSpanId } from "./turn-store";
import type { OtelSpan } from "./otel";
import { a } from "./otel";

function isoToMs(iso: string): number {
  return new Date(iso).getTime();
}

export function assembleSpans(turns: TurnRow[]): OtelSpan[] {
  const spans: OtelSpan[] = [];
  const nowMs = Date.now();

  for (const turn of turns) {
    const startMs = isoToMs(turn.started_at);
    const endMs = turn.ended_at ? isoToMs(turn.ended_at) : nowMs;

    const toolCalls: ToolCallEntry[] = (() => {
      try { return JSON.parse(turn.tool_calls); } catch { return []; }
    })();

    const llmCalls: LlmCallEntry[] = (() => {
      try { return JSON.parse(turn.llm_calls); } catch { return []; }
    })();

    const totalInputTokens  = llmCalls.reduce((s, l) => s + l.input_tokens,  0);
    const totalOutputTokens = llmCalls.reduce((s, l) => s + l.output_tokens, 0);
    const totalCostUsd      = llmCalls.reduce((s, l) => s + l.cost_usd,      0);

    // Root: one span per user-prompt → response cycle
    spans.push({
      traceId:    turn.trace_id,
      spanId:     turn.turn_id,
      name:       "kavachos.agent.turn",
      kind:       2, // SERVER
      startMs,
      endMs,
      attrs: [
        a.str("kavachos.session_id",          turn.session_id),
        a.int("kavachos.turn_number",         turn.turn_number),
        a.str("kavachos.prompt_preview",      turn.prompt_preview ?? ""),
        a.int("kavachos.tool_call_count",     toolCalls.length),
        a.int("kavachos.llm_call_count",      llmCalls.length),
        a.int("kavachos.total_input_tokens",  totalInputTokens),
        a.int("kavachos.total_output_tokens", totalOutputTokens),
        a.dbl("kavachos.total_cost_usd",      totalCostUsd),
      ],
      statusCode: 1,
    });

    // Child: one span per tool call
    for (const tc of toolCalls) {
      const tcStart = isoToMs(tc.started_at);
      const tcEnd   = tc.ended_at ? isoToMs(tc.ended_at) : tcStart + 100;
      spans.push({
        traceId:      turn.trace_id,
        spanId:       newSpanId(),
        parentSpanId: turn.turn_id,
        name:         `kavachos.tool.${tc.name}`,
        kind:         1, // INTERNAL
        startMs:      tcStart,
        endMs:        tcEnd,
        attrs: [
          a.str("kavachos.tool.name",          tc.name),
          a.str("kavachos.tool.input_preview", tc.input_preview),
          a.str("kavachos.turn_id",            turn.turn_id),
        ],
        statusCode: 1,
      });
    }

    // Child: one span per LLM call
    for (const lc of llmCalls) {
      const lcStart = isoToMs(lc.timestamp);
      spans.push({
        traceId:      turn.trace_id,
        spanId:       newSpanId(),
        parentSpanId: turn.turn_id,
        name:         "kavachos.llm.call",
        kind:         3, // CLIENT
        startMs:      lcStart,
        endMs:        lcStart + 500, // exact duration not tracked; LLM calls are min ~200ms
        attrs: [
          a.str("kavachos.llm.model",         lc.model),
          a.int("kavachos.llm.input_tokens",  lc.input_tokens),
          a.int("kavachos.llm.output_tokens", lc.output_tokens),
          a.dbl("kavachos.llm.cost_usd",      lc.cost_usd),
        ],
        statusCode: 1,
      });
    }
  }

  return spans;
}
