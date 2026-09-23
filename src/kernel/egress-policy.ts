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
/**
 * The resolvers this host is actually configured to use, read from /etc/resolv.conf.
 *
 * WHY THIS EXISTS. Every entry in this policy is a HOSTNAME. The supervisor resolves
 * them outside the cgroup when it fills the BPF map, so the map holds IPs — but the
 * agent inside the cgroup still has to resolve names for itself, and `connect()` on a
 * UDP socket to port 53 was never in the map. So every allowlisted host was reachable
 * by address and unreachable by name: curl returned exit 6, CURLE_COULDNT_RESOLVE_HOST,
 * against a host the policy explicitly permits. Found 2026-09-23, after the egress smoke
 * test stopped skipping on failure and reported it.
 *
 * NARROW BY CONSTRUCTION. Only the resolvers this box is configured with, only port 53.
 * Never a wildcard, because `anything:53` is an open DNS tunnel — a channel that carries
 * data out in query names regardless of what the rest of this allowlist says.
 *
 * THE CHANNEL THIS LEAVES, AND WHAT NOW CLOSES IT. A resolver is an exfiltration channel:
 * an agent can encode data into the names it asks that resolver to look up, and the
 * resolver forwards them. Allowing :53 here narrows nothing on its own — to the BPF
 * program a tunnelled query is a permitted packet to a permitted resolver on a permitted
 * port.
 *
 * That channel is now closed by the KOS-046 resolving proxy (src/kernel/dns-proxy.py):
 * connect4 steers every :53 connect() to it, and it answers ONLY for names this policy
 * already permits connecting to, refusing and recording the rest. The entries below are
 * therefore superseded at runtime and kept because the policy should still state that DNS
 * is permitted at all. If the proxy fails to start, dns_proxy_port stays 0 and the BPF
 * program denies :53 outright — the agent loses resolution rather than gaining a channel.
 *
 * @rule:INF-KOS-009 — an unreadable or empty resolv.conf returns NOTHING. It must never
 * fall back to permitting 53 broadly: a policy that cannot read its own inputs refuses,
 * and name resolution failing loudly is the correct outcome.
 */
export function systemResolvers(resolvConf = "/etc/resolv.conf"): EgressEntry[] {
  let text: string;
  try {
    text = require("fs").readFileSync(resolvConf, "utf-8");
  } catch {
    return [];
  }
  const out: EgressEntry[] = [];
  for (const line of text.split("\n")) {
    const m = line.trim().match(/^nameserver\s+(\S+)$/);
    if (!m) continue;
    const ip = m[1];
    if (out.some(e => e.host === ip)) continue;
    out.push({ host: ip, port: 53, note: "system DNS resolver (resolv.conf) — SUPERSEDED at runtime by the KOS-046 resolving proxy, which connect4 steers :53 to; kept so the policy still states that DNS is permitted at all" });
  }
  return out;
}

export function buildEgressPolicy(trustMask: number, domain: string): EgressPolicy {
  const allow: EgressEntry[] = [...BASE_ALLOW];

  // DNS to the configured resolvers, without which every hostname above is unreachable
  // by name. Declared here rather than injected when the BPF map is filled, so the
  // permission is visible in the policy a reader audits.
  allow.push(...systemResolvers());

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


/**
 * What a launch must do when the egress supervisor reports back. @rule:INF-KOS-009
 *
 * Extracted as a pure function because the rule is worth testing and a live collision is
 * not worth racing. Reproducing a real failed arm means holding BPF pins with one session
 * while a second starts on the same id — which is how the defect was found, and which
 * proved impossible to schedule reliably inside a smoke test. Three attempts produced
 * three different wrong diagnoses. The integration path is verified by hand; the RULE is
 * verified here, deterministically, in every combination.
 *
 * The verdict is whatever the supervisor wrote to the ready file: a cgroup path when it
 * armed, or one of the words below. Anything unrecognised is treated as a failure, never
 * as permission.
 */
export type EgressVerdict = string;
export type EgressAction = { proceed: boolean; reason: string };

export function egressLaunchDecision(verdict: EgressVerdict, allowUnconstrained: boolean): EgressAction {
  if (verdict.startsWith("/")) {
    return { proceed: true, reason: "egress armed" };
  }
  if (verdict === "UNAVAILABLE") {
    return allowUnconstrained
      ? { proceed: true, reason: "host cannot enforce egress; accepted by --allow-unconstrained-egress" }
      : { proceed: false, reason: "this host cannot enforce cgroup BPF egress. Pass --allow-unconstrained-egress to accept that deliberately." };
  }
  if (verdict === "FAILED") {
    // The flag accepts a host that CANNOT enforce. It never excuses one that could and did not.
    return { proceed: false, reason: "the egress session failed to arm on a host that supports it. That is a fault, not an environment." };
  }
  return { proceed: false, reason: `the egress supervisor reported '${verdict}'. Unknown is not permission.` };
}
