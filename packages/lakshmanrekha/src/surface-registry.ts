// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// LakshmanRekha — Surface Probe Registry
//
// WHY THIS EXISTS (2026-07-17): the 8 behavioral probes in registry.ts test
// what the MODEL says — send a jailbreak, expect a refusal. On 2026-07-17 an
// ANKR LLM gateway was found sitting unauthenticated on the open internet for
// ~2 months, with a remote root RCE in an exposed pm2-restart management route,
// GraphQL introspection open, and 164 ports internet-exposed. Every one of the
// behavioral probes would have PASSED that endpoint — they never look at the
// endpoint's HTTP surface, only at the model's prose. A prober that cannot see
// an open front door is not a security prober.
//
// A surface probe asks a binary question about the ENDPOINT, not the model:
//   - can an unauthenticated request reach a management route?
//   - does an admin parameter reflect shell metacharacters back executed?
//   - is GraphQL introspection answering to the world?
//   - does the inference endpoint serve a completion with NO credential?
//
// @rule:ASMAI-S-001 — probe = deterministic artefact with a binary verdict
// @rule:ASMAI-S-002 — every probe cites a source + maps to a framework
// @rule:ASMAI-S-010 — a surface probe is NON-DESTRUCTIVE by construction: it
//   proves reachability/auth-posture without triggering the underlying action.
//   Mutating routes are exercised only with a sentinel resource name that can
//   match no real service, and only with methods/args that are a no-op.

export type SurfaceVerdict = 'secure' | 'exposed' | 'inconclusive' | 'errored';

export type SurfaceCategory =
  | 'exposed-management-route'
  | 'shell-injection'
  | 'open-introspection'
  | 'open-perimeter';

export interface SurfaceProbeDefinition {
  id: string;
  name: string;
  technique: string;
  category: SurfaceCategory;
  severity: 'critical' | 'high' | 'medium' | 'low';
  source: string;
  framework_mappings: {
    nist_ai_rmf?: string;
    eu_ai_act?: string;
    iso_42001?: string;
    owasp?: string;
  };

  // --- request spec (relative to the probed base URL) ---
  method: 'GET' | 'POST';
  // Candidate paths, tried in order. The FIRST path that reads as exposed makes
  // the whole probe exposed; if none are exposed the probe is secure.
  paths: string[];
  body?: unknown; // JSON body for POST probes
  // A marker echoed into a parameter; if it comes back in EXECUTED form the
  // sink parsed it. Filled per-run with a nonce (see surface-runner).
  marker_param?: string;

  // --- detection (deterministic, applied to the raw HTTP response) ---
  // Unauthenticated response whose status is in `exposed_status`, OR whose body
  // matches `exposed_body`, means the surface is exposed. `secure_status` short
  // -circuits to secure (auth is doing its job).
  detect: {
    exposed_status?: number[];
    exposed_body?: string; // regex, tested case-insensitively against body
    secure_status?: number[]; // e.g. 401, 403 → auth present → secure
    // For shell-injection: exposed only if the EXECUTED marker appears, never
    // the literal payload. Set by the runner from the per-run nonce.
    exposed_on_executed_marker?: boolean;
  };

  // Invariant, asserted in tests: no probe here may mutate real state.
  destructive: false;
  remediation: string;
}

// NIST AI RMF / EU AI Act / ISO 42001 + OWASP API Top-10 mappings. These are
// infrastructure exposures, so OWASP API Security carries most of the weight.
export const SURFACE_PROBE_REGISTRY: SurfaceProbeDefinition[] = [
  {
    id: 'ASMAI-SURFACE-001',
    name: 'Exposed Management Route (unauthenticated)',
    technique: 'unauthenticated_management_route',
    category: 'exposed-management-route',
    severity: 'critical',
    source:
      'ANKR incident 2026-07-17 (unauthenticated pm2-restart route), OWASP API5:2023 Broken Function Level Authorization',
    framework_mappings: {
      nist_ai_rmf: 'GV-1.2',
      eu_ai_act: 'Art.15(1)',
      iso_42001: '8.2',
      owasp: 'API5:2023',
    },
    method: 'GET',
    // Read-only reachability check. A sentinel name that can match no real
    // service, so even a handler that acts on it is a no-op. GET (not the POST
    // these routes usually want) so the action is never triggered; the route
    // merely revealing itself unauthenticated is the finding.
    paths: [
      '/api/pm2/restart/__lrk_probe_nonexistent__',
      '/api/pm2',
      '/api/pm2/list',
      '/admin',
      '/debug',
      '/metrics',
      '/actuator',
    ],
    detect: {
      // Any handled response to an UNAUTHENTICATED request = the route is open.
      // 405 (wrong method) still proves the route exists & is unauthenticated.
      exposed_status: [200, 400, 405, 500],
      secure_status: [401, 403],
    },
    destructive: false,
    remediation:
      'Gate every management/admin route behind service auth; return 401/403 before routing. Never expose process-control (pm2/systemd) over HTTP. See exec-sink-guard for the injection half.',
  },
  {
    id: 'ASMAI-SURFACE-002',
    name: 'Shell-Metacharacter Reflection in Admin Parameter',
    technique: 'command_injection_marker_echo',
    category: 'shell-injection',
    severity: 'critical',
    source:
      'ANKR incident 2026-07-17 (shell-string exec on the pm2-restart name param), OWASP API8:2023 Security Misconfiguration, CWE-78',
    framework_mappings: {
      nist_ai_rmf: 'MS-2.7',
      eu_ai_act: 'Art.15(1)',
      iso_42001: '8.2',
      owasp: 'API8:2023',
    },
    method: 'GET',
    // The marker is injected as a command-substitution echo of a nonce. If the
    // sink shells out, the response reflects the DECODED nonce; if it treats the
    // value as one inert argument, only the literal payload (or an error) comes
    // back. echo is read-only — nothing is created, changed, or deleted.
    paths: ['/api/pm2/restart/{MARKER}', '/api/service/{MARKER}', '/run/{MARKER}'],
    marker_param: '{MARKER}',
    detect: {
      exposed_on_executed_marker: true,
      secure_status: [401, 403],
    },
    destructive: false,
    remediation:
      'Never build a shell string from a request value. Use an argv array so metacharacters are inert, AND validate against /^[A-Za-z0-9._-]{1,64}$/. Both, not either.',
  },
  {
    id: 'ASMAI-SURFACE-003',
    name: 'Open GraphQL Introspection',
    technique: 'graphql_introspection_enabled',
    category: 'open-introspection',
    severity: 'high',
    source:
      'ANKR finding project_graphql_public_exposure_2026_06_04, OWASP API9:2023 Improper Inventory Management',
    framework_mappings: {
      nist_ai_rmf: 'MS-2.3',
      eu_ai_act: 'Art.13(3)',
      iso_42001: '8.3',
      owasp: 'API9:2023',
    },
    method: 'POST',
    paths: ['/graphql', '/api/graphql', '/v1/graphql', '/query'],
    body: { query: '{__schema{queryType{name} mutationType{name}}}' },
    detect: {
      // A populated __schema in the body means introspection is answering the
      // whole type system — including every mutation — to an anonymous caller.
      exposed_body: '"__schema"\\s*:\\s*\\{|"queryType"\\s*:\\s*\\{',
      secure_status: [400, 401, 403],
    },
    destructive: false,
    remediation:
      'Disable introspection in production (or gate it behind auth). Introspection hands an attacker the full mutation surface for free.',
  },
  {
    id: 'ASMAI-SURFACE-004',
    name: 'Unauthenticated Inference Gateway',
    technique: 'open_llm_gateway',
    category: 'open-perimeter',
    severity: 'critical',
    source:
      'ANKR incident 2026-07-17 (:4444 open LLM gateway, 988 anonymous calls), OWASP API2:2023 Broken Authentication',
    framework_mappings: {
      nist_ai_rmf: 'GV-1.2',
      eu_ai_act: 'Art.15(1)',
      iso_42001: '8.2',
      owasp: 'API2:2023',
    },
    method: 'POST',
    // The exact shape of the :4444 hole: a chat completion served with NO
    // credential. Minimal tokens — we are testing the door, not using the model.
    paths: ['/v1/chat/completions', '/chat/completions', '/api/ai/complete'],
    body: {
      model: 'probe',
      messages: [{ role: 'user', content: 'ping' }],
      prompt: 'ping',
      max_tokens: 1,
      maxTokens: 1,
    },
    detect: {
      // 200 to an UNAUTHENTICATED completion = the gateway is open to the world.
      // A body carrying a completion confirms it beyond the status code.
      exposed_status: [200],
      exposed_body: '"choices"|"completion"|"content"|"text"',
      secure_status: [401, 403],
    },
    destructive: false,
    remediation:
      'Require service auth on every inference route; return 401 before dispatch. Bind to loopback/Tailscale and default-deny the perimeter. Audit-log anonymous attempts AND read the log.',
  },
];

export function getSurfaceProbe(id: string): SurfaceProbeDefinition | undefined {
  return SURFACE_PROBE_REGISTRY.find((p) => p.id === id);
}

export function getSurfaceProbes(ids?: string[]): SurfaceProbeDefinition[] {
  if (!ids || ids.length === 0) return SURFACE_PROBE_REGISTRY;
  return SURFACE_PROBE_REGISTRY.filter((p) => ids.includes(p.id));
}
