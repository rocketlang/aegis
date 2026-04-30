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

// @rule:KOS-013 domain-tuned rules — generic rules prohibited
export function generateFalcoRules(domain: string, trustMask: number): FalcoRuleSet {
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
    condition: `evt.type = execve and proc.name in (node, bun, claude) and not proc.args startswith "${ALLOWED_CLAUDE_BINARIES.slice(0, 8).join('" and not proc.args startswith "')}"`,
    output: "KavachOS: unexpected execve by AI agent (agent=%proc.name cmd=%proc.cmdline user=%user.name pid=%proc.pid)",
    priority: "WARNING",
    tags: ["kavachos", "process", "kos-infer-004"],
  });

  // Exfil pattern detection
  rules.push({
    name: "kavachos_exfil_command",
    desc: "AI agent attempted to execute a known data exfiltration command",
    condition: `evt.type = execve and (${EXFIL_COMMANDS.map((c) => `proc.cmdline contains "${c.split(" ")[0]}"`).join(" or ")})`,
    output: "KavachOS: EXFIL PATTERN detected (cmd=%proc.cmdline user=%user.name pid=%proc.pid container.id=%container.id)",
    priority: "CRITICAL",
    tags: ["kavachos", "exfil", "kos-007"],
  });

  // @rule:INF-KOS-002 violation rate — low-and-slow exfil prevention
  rules.push({
    name: "kavachos_file_write_outside_scope",
    desc: "AI agent wrote a file outside its declared working directory",
    condition: "evt.type in (open, openat) and evt.arg.flags contains O_WRONLY and not fd.name startswith /tmp and not fd.name startswith /root/.claude and not fd.name startswith /root/",
    output: "KavachOS: file write outside scope (file=%fd.name agent=%proc.name pid=%proc.pid)",
    priority: "WARNING",
    tags: ["kavachos", "file", "kos-003"],
  });

  // Credential file access
  rules.push({
    name: "kavachos_credential_read",
    desc: "AI agent read a credential or private key file",
    condition: `evt.type in (open, openat) and (fd.name contains ".pem" or fd.name contains ".key" or fd.name contains "id_rsa" or fd.name contains "credentials" or fd.name contains ".env" or fd.name endswith ".p12" or fd.name endswith ".pfx")`,
    output: "KavachOS: credential file access (file=%fd.name agent=%proc.name pid=%proc.pid)",
    priority: "ERROR",
    tags: ["kavachos", "credentials", "kos-007"],
  });

  // trust_mask=0 agents attempting network ops
  if (trustMask === 0) {
    rules.push({
      name: "kavachos_readonly_agent_network",
      desc: "Read-only agent (trust_mask=0) attempted network connection — violation of INF-KOS-001",
      condition: "evt.type in (connect, sendto, sendmsg) and proc.env contains KAVACHOS_TRUST_MASK=0",
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
    default:
      return generateGeneralRules(trustMask);
  }
}

// @rule:KOS-013 maritime-specific Falco rules — MAR-001 to MAR-008 aligned
function generateMaritimeRules(_trustMask: number): FalcoRule[] {
  return [
    {
      name: "kavachos_maritime_nmea_write",
      desc: "Agent wrote to NMEA serial device — potential navigation system tampering (MAR-001)",
      condition: "evt.type in (open, openat) and evt.arg.flags contains O_WRONLY and (fd.name startswith /dev/ttyS or fd.name startswith /dev/ttyUSB)",
      output: "KavachOS MARITIME: NMEA device write attempt (device=%fd.name agent=%proc.name pid=%proc.pid)",
      priority: "CRITICAL",
      tags: ["kavachos", "maritime", "nmea", "mar-001"],
    },
    {
      name: "kavachos_maritime_ais_inject",
      desc: "Agent attempted to write AIS position data — potential vessel spoofing (MAR-004)",
      condition: `evt.type = write and fd.name contains "ais" and evt.arg.data startswith "!AIVDM"`,
      output: "KavachOS MARITIME: AIS data injection attempt (agent=%proc.name pid=%proc.pid)",
      priority: "CRITICAL",
      tags: ["kavachos", "maritime", "ais", "mar-004"],
    },
    {
      name: "kavachos_maritime_stcw_data",
      desc: "Agent accessed STCW crew data file without maritime trust_mask bit set",
      condition: `evt.type in (open, openat) and (fd.name contains "stcw" or fd.name contains "crew" or fd.name contains "certificate") and not proc.env contains "KAVACHOS_DOMAIN=maritime"`,
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
      condition: `evt.type in (open, openat) and evt.arg.flags contains O_WRONLY and (fd.name contains "ebl" or fd.name contains "bill-of-lading") and not proc.env contains "KAVACHOS_EBL_AUTHORIZED=1"`,
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
      condition: `evt.type = sendto and fd.rport = 502 and evt.arg.data != ""`,
      output: "KavachOS OT: Modbus write detected (dst=%fd.rip:%fd.rport agent=%proc.name pid=%proc.pid)",
      priority: "CRITICAL",
      tags: ["kavachos", "ot", "modbus", "iec-62443"],
    },
    {
      name: "kavachos_ot_alarm_suppress",
      desc: "Agent suppressed an OT alarm signal — critical safety violation",
      condition: `evt.type = write and (fd.name contains "alarm" or fd.name contains "safety") and evt.arg.data contains "suppress"`,
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
      condition: `evt.type = sendto and (fd.rport = 443 or fd.rport = 8443) and proc.env contains "PAYMENT_INSTRUCTION" and not proc.env contains "KAVACHOS_FIN_AUTHORIZED=1"`,
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
      condition: `evt.type = execve and (proc.name = "bash" or proc.name = "sh" or proc.name = "zsh") and proc.args contains "-i"`,
      output: "KavachOS: interactive shell spawn by AI agent (agent=%proc.name cmd=%proc.cmdline pid=%proc.pid)",
      priority: "WARNING",
      tags: ["kavachos", "general", "shell"],
    },
  ];
}

function buildYaml(rules: FalcoRule[]): string {
  return rules.map((r) => `
- rule: ${r.name}
  desc: ${r.desc}
  condition: >
    ${r.condition}
  output: "${r.output}"
  priority: ${r.priority}
  tags: [${r.tags.join(", ")}]
`).join("\n");
}
