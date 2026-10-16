// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// @rule:KOS-013 Falco rules are domain-specific, not generic

export interface FalcoRuleSet {
  version: "1.0";
  domain: string;
  trust_mask: number;
  rules: string;  // YAML string
  rule_count: number;
  generated_at: string;
}

const EXFIL_COMMANDS = [
  "curl", "wget", "nc", "ncat", "netcat",
  "python3 -c", "python -c",  // inline network scripts
  "bash -i",  // interactive shell spawns
  "sh -i",
  "socat",
  "openssl s_client",
];

const ALLOWED_CLAUDE_BINARIES = [
  "node", "bun", "claude", "git", "npm", "npx",
  "cat", "grep", "ls", "find", "sed", "awk",
  "head", "tail", "wc", "sort", "uniq",
  "mkdir", "cp", "mv", "rm", "touch",
  "tar", "gzip", "gunzip",
  "psql", "pg_dump",
  "docker",
  "python3", "python",
  "bash", "sh", "zsh",
];

// Every value placed in a Falco condition goes through q(), which always quotes and escapes it.
// Values used to be typed into each condition by hand, quoted or not by habit; one unquoted
// KAVACHOS_TRUST_MASK=0 made Falco reject the read-only agent's whole ruleset (clean-bench run,
// 2026-10-16). tests/falco-env-quoted.test.ts refuses a hand-written quoted operand in this file.
export function q(value: string): string {
  if (/[\r\n]/.test(value)) throw new Error(`Falco condition value contains a line break: ${JSON.stringify(value)}`);
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}
const envHas = (v: string) => `proc.env contains ${q(v)}`;
const nameHas = (v: string) => `fd.name contains ${q(v)}`;
const WRITE_FLAG = `evt.arg.flags contains ${q("O_WRONLY")}`;

// The domains that have their own rules, and the names accepted for them. Anything else is refused:
// an unknown name used to fall through to the general rules without a word, so --domain=freight
// silently got a ruleset with no freight rules in it.
export const FALCO_DOMAINS = ["maritime", "logistics", "ot", "finance", "general"] as const;
export const FALCO_DOMAIN_ALIASES: Record<string, (typeof FALCO_DOMAINS)[number]> = { freight: "logistics" };

export class UnknownFalcoDomainError extends Error {
  constructor(domain: string) {
    super(`unknown Falco domain '${domain}': use one of ${[...FALCO_DOMAINS, ...Object.keys(FALCO_DOMAIN_ALIASES)].join(", ")}`);
    this.name = "UnknownFalcoDomainError";
  }
}

export function resolveFalcoDomain(domain: string): (typeof FALCO_DOMAINS)[number] {
  if ((FALCO_DOMAINS as readonly string[]).includes(domain)) return domain as (typeof FALCO_DOMAINS)[number];
  const alias = FALCO_DOMAIN_ALIASES[domain];
  if (alias) return alias;
  throw new UnknownFalcoDomainError(domain);
}

// @rule:KOS-013 domain-tuned rules — generic rules prohibited
export function generateFalcoRules(requestedDomain: string, trustMask: number): FalcoRuleSet {
  const domain = resolveFalcoDomain(requestedDomain);
  const baseRules = generateBaseRules(trustMask);
  const domainRules = generateDomainRules(domain, trustMask);
  const allRules = [...baseRules, ...domainRules];

  const yaml = buildYaml(allRules);

  return {
    version: "1.0",
    domain,
    trust_mask: trustMask,
    rules: yaml,
    rule_count: allRules.length,
    generated_at: new Date().toISOString(),
  };
}

interface FalcoRule {
  name: string;
  desc: string;
  condition: string;
  output: string;
  priority: "CRITICAL" | "ERROR" | "WARNING" | "NOTICE" | "INFO";
  tags: string[];
}

function generateBaseRules(trustMask: number): FalcoRule[] {
  const rules: FalcoRule[] = [];

  // @rule:INF-KOS-004 unexpected execve → Falco → PRAMANA → quarantine
  rules.push({
    name: "kavachos_unexpected_execve",
    desc: "AI agent executed a binary not in the declared tool scope (potential exfil or lateral movement)",
    condition: `evt.type = execve and proc.name in (node, bun, claude) and ${ALLOWED_CLAUDE_BINARIES.slice(0, 8).map((b) => `not proc.args startswith ${q(b)}`).join(" and ")}`,
    output: "KavachOS: unexpected execve by AI agent (agent=%proc.name cmd=%proc.cmdline user=%user.name pid=%proc.pid)",
    priority: "WARNING",
    tags: ["kavachos", "process", "kos-infer-004"],
  });

  // Exfil pattern detection
  rules.push({
    name: "kavachos_exfil_command",
    desc: "AI agent attempted to execute a known data exfiltration command",
    condition: `evt.type = execve and (${EXFIL_COMMANDS.map((c) => `proc.cmdline contains ${q(c.split(" ")[0])}`).join(" or ")})`,
    output: "KavachOS: EXFIL PATTERN detected (cmd=%proc.cmdline user=%user.name pid=%proc.pid container.id=%container.id)",
    priority: "CRITICAL",
    tags: ["kavachos", "exfil", "kos-007"],
  });

  // @rule:INF-KOS-002 violation rate — low-and-slow exfil prevention
  rules.push({
    name: "kavachos_file_write_outside_scope",
    desc: "AI agent wrote a file outside its declared working directory",
    condition: `evt.type in (open, openat) and ${WRITE_FLAG} and not fd.name startswith ${q("/tmp")} and not fd.name startswith ${q("/root/.claude")} and not fd.name startswith ${q("/root/")}`,
    output: "KavachOS: file write outside scope (file=%fd.name agent=%proc.name pid=%proc.pid)",
    priority: "WARNING",
    tags: ["kavachos", "file", "kos-003"],
  });

  // Credential file access
  rules.push({
    name: "kavachos_credential_read",
    desc: "AI agent read a credential or private key file",
    condition: `evt.type in (open, openat) and (${[".pem", ".key", "id_rsa", "credentials", ".env"].map(nameHas).join(" or ")} or fd.name endswith ${q(".p12")} or fd.name endswith ${q(".pfx")})`,
    output: "KavachOS: credential file access (file=%fd.name agent=%proc.name pid=%proc.pid)",
    priority: "ERROR",
    tags: ["kavachos", "credentials", "kos-007"],
  });

  // trust_mask=0 agents attempting network ops
  if (trustMask === 0) {
    rules.push({
      name: "kavachos_readonly_agent_network",
      desc: "Read-only agent (trust_mask=0) attempted network connection — violation of INF-KOS-001",
      condition: `evt.type in (connect, sendto, sendmsg) and ${envHas("KAVACHOS_TRUST_MASK=0")}`,
      output: "KavachOS: read-only agent network attempt BLOCKED (agent=%proc.name dst=%fd.rip pid=%proc.pid)",
      priority: "CRITICAL",
      tags: ["kavachos", "trust-mask-zero", "inf-kos-001"],
    });
  }

  return rules;
}

function generateDomainRules(domain: string, trustMask: number): FalcoRule[] {
  switch (domain) {
    case "maritime":
      return generateMaritimeRules(trustMask);
    case "logistics":
      return generateLogisticsRules(trustMask);
    case "ot":
      return generateOTRules(trustMask);
    case "finance":
      return generateFinanceRules(trustMask);
    case "general":
      return generateGeneralRules(trustMask);
    default:
      throw new UnknownFalcoDomainError(domain);
  }
}

// @rule:KOS-013 maritime-specific Falco rules — MAR-001 to MAR-008 aligned
function generateMaritimeRules(_trustMask: number): FalcoRule[] {
  return [
    {
      name: "kavachos_maritime_nmea_write",
      desc: "Agent wrote to NMEA serial device — potential navigation system tampering (MAR-001)",
      condition: `evt.type in (open, openat) and ${WRITE_FLAG} and (fd.name startswith ${q("/dev/ttyS")} or fd.name startswith ${q("/dev/ttyUSB")})`,
      output: "KavachOS MARITIME: NMEA device write attempt (device=%fd.name agent=%proc.name pid=%proc.pid)",
      priority: "CRITICAL",
      tags: ["kavachos", "maritime", "nmea", "mar-001"],
    },
    {
      name: "kavachos_maritime_ais_inject",
      desc: "Agent attempted to write AIS position data — potential vessel spoofing (MAR-004)",
      condition: `evt.type = write and ${nameHas("ais")} and evt.arg.data startswith ${q("!AIVDM")}`,
      output: "KavachOS MARITIME: AIS data injection attempt (agent=%proc.name pid=%proc.pid)",
      priority: "CRITICAL",
      tags: ["kavachos", "maritime", "ais", "mar-004"],
    },
    {
      name: "kavachos_maritime_stcw_data",
      desc: "Agent accessed STCW crew data file without maritime trust_mask bit set",
      condition: `evt.type in (open, openat) and (${["stcw", "crew", "certificate"].map(nameHas).join(" or ")}) and not ${envHas("KAVACHOS_DOMAIN=maritime")}`,
      output: "KavachOS MARITIME: STCW data accessed without maritime clearance (file=%fd.name agent=%proc.name)",
      priority: "ERROR",
      tags: ["kavachos", "maritime", "stcw", "inf-kos-005"],
    },
  ];
}

function generateLogisticsRules(_trustMask: number): FalcoRule[] {
  return [
    {
      name: "kavachos_logistics_ebl_write",
      desc: "Agent wrote to eBL document store without eBL trust bit — potential document fraud",
      condition: `evt.type in (open, openat) and ${WRITE_FLAG} and (${["ebl", "bill-of-lading"].map(nameHas).join(" or ")}) and not ${envHas("KAVACHOS_EBL_AUTHORIZED=1")}`,
      output: "KavachOS LOGISTICS: unauthorized eBL write (file=%fd.name agent=%proc.name pid=%proc.pid)",
      priority: "ERROR",
      tags: ["kavachos", "logistics", "ebl"],
    },
  ];
}

function generateOTRules(_trustMask: number): FalcoRule[] {
  return [
    {
      name: "kavachos_ot_modbus_write",
      desc: "Agent wrote to Modbus register — potential OT control system manipulation (IEC 62443)",
      condition: `evt.type = sendto and fd.rport = 502 and evt.arg.data != ${q("")}`,
      output: "KavachOS OT: Modbus write detected (dst=%fd.rip:%fd.rport agent=%proc.name pid=%proc.pid)",
      priority: "CRITICAL",
      tags: ["kavachos", "ot", "modbus", "iec-62443"],
    },
    {
      name: "kavachos_ot_alarm_suppress",
      desc: "Agent suppressed an OT alarm signal — critical safety violation",
      condition: `evt.type = write and (${["alarm", "safety"].map(nameHas).join(" or ")}) and evt.arg.data contains ${q("suppress")}`,
      output: "KavachOS OT: ALARM SUPPRESS attempt (file=%fd.name agent=%proc.name pid=%proc.pid)",
      priority: "CRITICAL",
      tags: ["kavachos", "ot", "safety", "varuna"],
    },
  ];
}

function generateFinanceRules(_trustMask: number): FalcoRule[] {
  return [
    {
      name: "kavachos_fin_payment_write",
      desc: "Agent wrote payment instruction without financial authorization trust bit",
      condition: `evt.type = sendto and (fd.rport = 443 or fd.rport = 8443) and ${envHas("PAYMENT_INSTRUCTION")} and not ${envHas("KAVACHOS_FIN_AUTHORIZED=1")}`,
      output: "KavachOS FIN: unauthorized payment instruction (agent=%proc.name dst=%fd.rip pid=%proc.pid)",
      priority: "CRITICAL",
      tags: ["kavachos", "finance", "payment", "kos-fin-class3"],
    },
  ];
}

function generateGeneralRules(_trustMask: number): FalcoRule[] {
  return [
    {
      name: "kavachos_general_shell_spawn",
      desc: "Agent spawned an interactive shell — potential container escape vector",
      condition: `evt.type = execve and (${["bash", "sh", "zsh"].map((n) => `proc.name = ${q(n)}`).join(" or ")}) and proc.args contains ${q("-i")}`,
      output: "KavachOS: interactive shell spawn by AI agent (agent=%proc.name cmd=%proc.cmdline pid=%proc.pid)",
      priority: "WARNING",
      tags: ["kavachos", "general", "shell"],
    },
  ];
}

function buildYaml(rules: FalcoRule[]): string {
  return rules.map((r) => `
- rule: ${r.name}
  desc: ${JSON.stringify(r.desc)}
  condition: >
    ${r.condition}
  output: ${JSON.stringify(r.output)}
  priority: ${r.priority}
  tags: [${r.tags.join(", ")}]
`).join("\n");
}
