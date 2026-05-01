// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// @rule:KOS-091 OTLP trace spans per agent turn — no SDK, no cold-start overhead
//
// Implements OpenTelemetry Traces signal over OTLP/HTTP/JSON (OTLP spec 1.0).
// Compatible with: Grafana Tempo (:4318), Jaeger (:4318), Datadog Agent (:4318),
//                  LangSmith OTLP endpoint, Honeycomb.

// ── Attribute helpers ──────────────────────────────────────────────────────────

export type AttrValue =
  | { stringValue: string }
  | { intValue: number }
  | { doubleValue: number }
  | { boolValue: boolean };

export interface Attr { key: string; value: AttrValue; }

export const a = {
  str:  (key: string, v: string): Attr   => ({ key, value: { stringValue: v } }),
  int:  (key: string, v: number): Attr   => ({ key, value: { intValue: v } }),
  dbl:  (key: string, v: number): Attr   => ({ key, value: { doubleValue: v } }),
  bool: (key: string, v: boolean): Attr  => ({ key, value: { boolValue: v } }),
};

// ── Span definition ────────────────────────────────────────────────────────────

export interface OtelSpan {
  traceId: string;       // 32 hex chars (128-bit)
  spanId: string;        // 16 hex chars (64-bit)
  parentSpanId?: string; // absent on root spans
  name: string;
  kind?: 1 | 2 | 3;     // INTERNAL=1 SERVER=2 CLIENT=3
  startMs: number;       // epoch millis
  endMs: number;
  attrs: Attr[];
  statusCode?: 1 | 2;   // OK=1 ERROR=2
  statusMsg?: string;
}

// ── Nano conversion (OTLP requires nanosecond strings) ─────────────────────────

function msToNano(ms: number): string {
  return (BigInt(Math.floor(ms)) * 1_000_000n).toString();
}

// ── OTLP HTTP JSON export ──────────────────────────────────────────────────────

export interface ExportConfig {
  endpoint: string;                  // e.g. "http://localhost:4318/v1/traces"
  headers: Record<string, string>;   // e.g. { "x-api-key": "..." } for LangSmith
  serviceName: string;
  serviceVersion: string;
  resourceAttrs: Attr[];
}

export async function exportSpans(cfg: ExportConfig, spans: OtelSpan[]): Promise<void> {
  if (spans.length === 0) return;

  const otlpSpans = spans.map((s) => ({
    traceId: s.traceId,
    spanId: s.spanId,
    ...(s.parentSpanId ? { parentSpanId: s.parentSpanId } : {}),
    name: s.name,
    kind: s.kind ?? 1,
    startTimeUnixNano: msToNano(s.startMs),
    endTimeUnixNano: msToNano(Math.max(s.endMs, s.startMs + 1)),  // never zero-duration
    attributes: s.attrs,
    status: { code: s.statusCode ?? 1, message: s.statusMsg ?? "" },
  }));

  const payload = {
    resourceSpans: [{
      resource: {
        attributes: [
          a.str("service.name", cfg.serviceName),
          a.str("service.version", cfg.serviceVersion),
          ...cfg.resourceAttrs,
        ],
      },
      scopeSpans: [{
        scope: { name: "kavachos.agent", version: cfg.serviceVersion },
        spans: otlpSpans,
      }],
    }],
  };

  const resp = await fetch(cfg.endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...cfg.headers },
    body: JSON.stringify(payload),
    // @rule:KOS-091 non-blocking export — fail silently rather than block session end
    signal: AbortSignal.timeout(5_000),
  });

  if (!resp.ok) {
    throw new Error(`OTLP HTTP ${resp.status}: ${await resp.text().catch(() => "")}`);
  }
}
