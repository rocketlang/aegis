// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// LakshmanRekha — Surface Probe Execution Engine
//
// Executes SurfaceProbeDefinition specs against an endpoint's HTTP surface and
// returns a deterministic binary verdict (secure | exposed | inconclusive |
// errored). Unlike the behavioral runner it does NOT call an LLM or classify
// prose — it inspects raw HTTP responses (status, body) of unauthenticated
// requests.
//
// @rule:ASMAI-S-006 — ownership verification is the CALLER's responsibility.
//   These probes touch management routes. Probing an endpoint you do not own
//   or lack written consent to test is the caller's legal responsibility.
// @rule:ASMAI-S-010 — NON-DESTRUCTIVE by construction. Requests are sent WITHOUT
//   credentials (the whole point is to prove auth is absent), mutating routes
//   are hit only with sentinel names, and the injection probe uses a read-only
//   `echo` of a random nonce — never a state-changing command.

import type { SurfaceProbeDefinition, SurfaceVerdict } from './surface-registry.js';
import { emitAccReceipt } from './acc-bus.js';

export interface RunSurfaceProbeOptions {
  probe: SurfaceProbeDefinition;
  base_url: string; // scheme://host[:port] — paths from the probe are appended
  timeout_ms?: number;
  // Optional: a nonce for the shell-injection marker. Supply for deterministic
  // tests; otherwise the caller passes one derived from a non-time source.
  nonce?: string;
}

export interface SurfaceProbeResult {
  probe_id: string;
  verdict: SurfaceVerdict;
  category: SurfaceProbeDefinition['category'];
  severity: SurfaceProbeDefinition['severity'];
  duration_ms: number;
  // The path that produced the verdict (the first exposed one, or the last
  // tried). Never includes credentials — none are sent.
  matched_path?: string;
  status?: number;
  evidence?: string; // <=200 chars, WHY the verdict — never the full body
  error?: string;
}

// A single unauthenticated HTTP request. No Authorization header — by design.
async function probeRequest(
  url: string,
  method: 'GET' | 'POST',
  body: unknown,
  timeout_ms: number
): Promise<{ status: number; body: string }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout_ms);
  try {
    const init: RequestInit = { method, signal: controller.signal, redirect: 'manual' };
    if (method === 'POST') {
      init.headers = { 'Content-Type': 'application/json' };
      init.body = JSON.stringify(body ?? {});
    }
    const res = await fetch(url, init);
    // Cap the body read — evidence needs a snippet, not the whole response.
    const text = (await res.text()).slice(0, 4096);
    return { status: res.status, body: text };
  } finally {
    clearTimeout(timer);
  }
}

const joinUrl = (base: string, path: string): string =>
  base.replace(/\/$/, '') + (path.startsWith('/') ? path : `/${path}`);

// Deterministic classification of one HTTP response against a probe's detect
// spec. Returns null when this response is neither clearly exposed nor clearly
// secure (caller keeps trying other paths, else falls through to inconclusive).
function classifyResponse(
  probe: SurfaceProbeDefinition,
  status: number,
  body: string,
  marker: { nonce: string; literal: string } | null
): { verdict: SurfaceVerdict; evidence: string } | null {
  const d = probe.detect;

  // Auth present → secure wins immediately, regardless of anything else.
  if (d.secure_status?.includes(status)) {
    return { verdict: 'secure', evidence: `HTTP ${status} — auth rejected the unauthenticated request` };
  }

  // Shell-injection: exposed ONLY if the EXECUTED marker is reflected. Critical
  // subtlety (SR-021): the literal payload REFLECTED back also contains the
  // nonce as a substring — that is CORRECT escaping, not a finding. So strip
  // every occurrence of the literal payload first; only a BARE nonce surviving
  // that means the command substitution actually ran.
  if (d.exposed_on_executed_marker && marker) {
    const stripped = body.split(marker.literal).join('');
    if (stripped.includes(marker.nonce)) {
      return {
        verdict: 'exposed',
        evidence: `bare marker "${marker.nonce}" reflected (literal payload stripped) — the value was shell-executed`,
      };
    }
    // Either the nonce never appeared, or it appeared only inside the literal
    // payload (safely escaped). Both mean the sink did NOT execute it.
    return { verdict: 'secure', evidence: 'injected marker was not executed (value treated as inert)' };
  }

  // Body signature (e.g. a populated __schema, a served completion).
  if (d.exposed_body) {
    try {
      if (new RegExp(d.exposed_body, 'i').test(body)) {
        return { verdict: 'exposed', evidence: `HTTP ${status}, body matched exposure signature /${d.exposed_body}/` };
      }
    } catch {
      /* a bad regex in a probe def must not crash the run */
    }
  }

  // Status-only exposure (route answered an unauthenticated request).
  if (d.exposed_status?.includes(status)) {
    return { verdict: 'exposed', evidence: `HTTP ${status} — route handled an UNAUTHENTICATED request` };
  }

  return null; // undecided on this path
}

export async function runSurfaceProbe(opts: RunSurfaceProbeOptions): Promise<SurfaceProbeResult> {
  const { probe, base_url, timeout_ms = 8000 } = opts;
  const t0 = Date.now();
  const base = {
    probe_id: probe.id,
    category: probe.category,
    severity: probe.severity,
  } as const;

  // Read-only marker for the injection probe: echo a random nonce via command
  // substitution. If executed it prints the nonce and nothing else happens.
  const nonce = opts.nonce ?? `LRK${Math.abs(hashString(probe.id + base_url)).toString(36)}`;
  // Read-only command substitution. `literalDecoded` is what a SAFE server
  // reflects verbatim (URL-decoded); `injectionPayload` is what goes on the wire.
  const literalDecoded = `$(echo ${nonce})`;
  const marker = probe.marker_param ? { nonce, literal: literalDecoded } : null;
  const injectionPayload = probe.marker_param ? encodeURIComponent(literalDecoded) : null;

  let lastStatus: number | undefined;
  let lastEvidence: string | undefined;

  try {
    for (const rawPath of probe.paths) {
      const path = probe.marker_param && injectionPayload
        ? rawPath.replace(probe.marker_param, injectionPayload)
        : rawPath;
      const url = joinUrl(base_url, path);

      let status: number, body: string;
      try {
        ({ status, body } = await probeRequest(url, probe.method, probe.body, timeout_ms));
      } catch (err) {
        // A single path failing (timeout, DNS, connection refused) is not the
        // whole probe failing — a refused connection may itself mean secure
        // (port closed). Record and keep trying the other paths.
        lastEvidence = `path ${path}: ${err instanceof Error ? err.message : String(err)}`;
        continue;
      }

      lastStatus = status;
      const decided = classifyResponse(probe, status, body, marker);
      if (decided) {
        // Exposed short-circuits the whole probe; secure only short-circuits if
        // it is a definitive auth rejection (already handled inside classify).
        if (decided.verdict === 'exposed') {
          return finish('exposed', decided.evidence, path, status);
        }
        if (decided.verdict === 'secure') {
          lastEvidence = decided.evidence;
          // keep the first definitive secure but continue in case another path
          // is exposed — exposure anywhere dominates.
        }
      }
      lastEvidence = lastEvidence ?? `HTTP ${status} — no exposure signature on ${path}`;
    }

    // No path was exposed. If we ever saw a definitive secure, call it secure;
    // otherwise every path errored/was undecided → inconclusive.
    if (lastStatus === undefined) {
      return finish('inconclusive', lastEvidence ?? 'all paths unreachable', undefined, undefined);
    }
    // Reaching here with a real status and no exposure = secure surface.
    return finish('secure', lastEvidence ?? `no exposure across ${probe.paths.length} path(s)`, undefined, lastStatus);
  } catch (err) {
    return finish('errored', err instanceof Error ? err.message.slice(0, 200) : String(err), undefined, undefined);
  }

  function finish(
    verdict: SurfaceVerdict,
    evidence: string,
    matched_path: string | undefined,
    status: number | undefined
  ): SurfaceProbeResult {
    const duration_ms = Date.now() - t0;
    emitAccReceipt({
      receipt_id: `lakshman-surface-${probe.id}-${t0}`,
      event_type: 'surface_probe.run',
      verdict: verdict === 'secure' ? 'refused' : verdict === 'exposed' ? 'complied' : verdict,
      rules_fired: ['ASMAI-S-001', 'ASMAI-S-002', 'ASMAI-S-010'],
      summary: `${probe.id} (${probe.severity}/${probe.category}) → ${verdict} (${duration_ms}ms)`,
      payload: {
        probe_name: probe.name,
        technique: probe.technique,
        surface_verdict: verdict,
        matched_path,
        status,
        endpoint_host: (() => { try { return new URL(base_url).host; } catch { return 'unknown'; } })(),
      },
    });
    return {
      ...base,
      verdict,
      duration_ms,
      matched_path,
      status,
      evidence: evidence.slice(0, 200),
      ...(verdict === 'errored' ? { error: evidence.slice(0, 200) } : {}),
    };
  }
}

// Run every surface probe against one endpoint, sequentially. Exposure anywhere
// is what matters, so order is irrelevant; sequential keeps load on the target
// minimal (these hit management routes).
export async function runAllSurfaceProbes(
  base_url: string,
  options?: { timeout_ms?: number; probe_ids?: string[] }
): Promise<SurfaceProbeResult[]> {
  const { SURFACE_PROBE_REGISTRY, getSurfaceProbes } = await import('./surface-registry.js');
  const probes = options?.probe_ids ? getSurfaceProbes(options.probe_ids) : SURFACE_PROBE_REGISTRY;
  const results: SurfaceProbeResult[] = [];
  for (const probe of probes) {
    results.push(await runSurfaceProbe({ probe, base_url, timeout_ms: options?.timeout_ms }));
  }
  return results;
}

// Aggregate: how many surfaces are exposed. 0 exposed = the endpoint passed the
// surface suite. Mirrors computeRefusalRate's role for the behavioral suite.
export function countExposed(results: SurfaceProbeResult[]): {
  exposed: number;
  secure: number;
  inconclusive: number;
  errored: number;
  total: number;
} {
  const tally = { exposed: 0, secure: 0, inconclusive: 0, errored: 0, total: results.length };
  for (const r of results) tally[r.verdict]++;
  return tally;
}

// Small deterministic non-crypto hash (FNV-1a) — used only to derive a stable
// nonce from the probe id + target when the caller does not supply one. NOT a
// security primitive; it just needs to be reproducible and time-independent.
function hashString(s: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h | 0;
}
