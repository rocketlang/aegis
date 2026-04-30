// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// @rule:KOS-042 egress allowlist declared at launch — no runtime expansion
// @rule:KOS-043 domain-derived IP:port tuples — deterministic, not configuration-dependent

/**
 * KavachOS egress policy — Phase 1E
 *
 * Maps (domain, trust_mask) → allowed egress destinations.
 * The cgroup BPF program uses these as its allowlist — anything
 * not listed is denied at connect() before the socket is established.
 *
 * Rule KOS-040: egress firewall = cgroup BPF CONNECT4/6, bytes denied before established.
 * Rule INF-KOS-009: empty allowlist → deny-all. Never default-open.
 */

export interface EgressEntry {
  host: string;   // FQDN or IP
  port: number;   // 0 = any port for this host
  note?: string;  // human label for the ledger
}

export interface EgressPolicy {
  domain: string;
  trust_mask: number;
  allow: EgressEntry[];
  // Resolved at launch — populated by resolveEgressPolicy()
  resolved?: Array<{ ip: string; port: number; note: string }>;
}

// @rule:KOS-042 domain-anchored egress — the LLM API + domain-specific endpoints
const BASE_ALLOW: EgressEntry[] = [
  { host: "api.anthropic.com",         port: 443, note: "Anthropic API" },
  { host: "api.openai.com",            port: 443, note: "OpenAI API" },
  { host: "generativelanguage.googleapis.com", port: 443, note: "Gemini API" },
  { host: "api.groq.com",              port: 443, note: "Groq API (free_first)" },
  { host: "api-inference.huggingface.co", port: 443, note: "HF Inference (free_first)" },
];

const DOMAIN_EXTRA: Record<string, EgressEntry[]> = {
  general: [
    { host: "github.com",          port: 443, note: "GitHub API" },
    { host: "raw.githubusercontent.com", port: 443, note: "GitHub raw" },
    { host: "registry.npmjs.org",  port: 443, note: "npm registry" },
  ],
  maritime: [
    { host: "api.aisstream.io",    port: 443, note: "AIS stream" },
    { host: "maddox.iho.int",      port: 443, note: "IHO chart service" },
    // NMEA/AIS typically local network — localhost ports allowed
    { host: "127.0.0.1",           port: 0,   note: "localhost (NMEA/Modbus)" },
  ],
  logistics: [
    { host: "api.searates.com",    port: 443, note: "freight rates" },
    { host: "api.bolero.net",      port: 443, note: "eBL platform" },
  ],
  ot: [
    { host: "127.0.0.1",           port: 0,   note: "localhost (Modbus/NMEA/AIS)" },
  ],
  finance: [
    { host: "api.stripe.com",      port: 443, note: "Stripe" },
    { host: "sandbox.hsm.example", port: 443, note: "HSM API" },
  ],
};

// Trust-mask bit extensions for egress
const TRUST_MASK_EGRESS: Record<number, EgressEntry[]> = {
  // bit 3 (db) — allow direct DB connections to registered DB servers
  // bit 4 (notification) — mail relay
  4: [{ host: "smtp.mailgun.org", port: 587, note: "Mailgun SMTP" }],
  // bit 6 (registered) — allow localhost services
  6: [
    { host: "localhost", port: 0,    note: "localhost" },
    { host: "127.0.0.1", port: 0,   note: "localhost" },
  ],
};

// @rule:KOS-042 deterministic: same (domain, trust_mask) → same policy
export function buildEgressPolicy(trustMask: number, domain: string): EgressPolicy {
  const allow: EgressEntry[] = [...BASE_ALLOW];

  // Domain extras
  const extras = DOMAIN_EXTRA[domain] ?? DOMAIN_EXTRA.general;
  allow.push(...extras);

  // Trust-mask bit extensions
  for (let bit = 0; bit < 32; bit++) {
    if (trustMask & (1 << bit)) {
      const extra = TRUST_MASK_EGRESS[bit] ?? [];
      allow.push(...extra);
    }
  }

  if (!(trustMask & (1 << 6))) {
    allow.push({ host: "127.0.0.1", port: 0, note: "loopback" });
    allow.push({ host: "::1",       port: 0, note: "loopback IPv6" });
  }

  return { domain, trust_mask: trustMask, allow };
}

// ANKR AI Proxy override — all LLM calls go through the local proxy first
export function withAiProxyOverride(policy: EgressPolicy, proxyPort: number): EgressPolicy {
  return {
    ...policy,
    allow: [
      ...policy.allow.filter((e) => !isLlmApiHost(e.host)),
      { host: "127.0.0.1", port: proxyPort, note: `ANKR AI Proxy (free_first, port ${proxyPort})` },
    ],
  };
}

function isLlmApiHost(host: string): boolean {
  return host.includes("anthropic") || host.includes("openai") || host.includes("groq") ||
    host.includes("huggingface") || host.includes("googleapis");
}

// Serialise to JSON for the Python BPF loader
export function serialiseEgressPolicy(policy: EgressPolicy): string {
  return JSON.stringify(policy, null, 2);
}
