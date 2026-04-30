#!/usr/bin/env bun
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// @rule:KOS-011 kavachos run — the only approved agent launch path

// kavachos <command> [options]
//
// Commands:
//   run <agent> [args]           Launch agent under seccomp + Falco governance
//   generate                     Generate profile only (no exec)
//   profile show <agent-id>      Display active seccomp profile + gate valve state
//   audit [session-id]           Verify profile hash + receipt chain
//   rules                        Print Falco rules for a domain
//   init                         Write .kavachos.json config in project root
//   version                      Print version

const command = Bun.argv[2] || "help";
const subCommand = Bun.argv[3];
const args = Bun.argv.slice(3);

async function main() {
  switch (command) {
    case "run":
      return cmdRun(args);
    case "generate":
    case "gen":
      return cmdGenerate(args);
    case "profile":
      if (subCommand === "show") return cmdProfileShow(Bun.argv.slice(4));
      console.error(`Unknown profile sub-command: ${subCommand}. Try: kavachos profile show <agent-id>`);
      process.exit(1);
      break;
    case "audit":
      return cmdAudit(args);
    case "rules":
      return cmdRules(args);
    case "init":
      return cmdInit(args);
    case "version":
    case "--version":
    case "-v":
      console.log("kavachos 2.0.0 (KavachOS KERNEL — xShieldAI Posture Suite)");
      console.log("AGPL-3.0 · DOI 10.5281/zenodo.19908430");
      break;
    case "help":
    case "--help":
    case "-h":
      printHelp();
      break;
    default:
      console.error(`Unknown command: ${command}`);
      printHelp();
      process.exit(1);
  }
}

// kavachos run <agent_binary> [agent_args] --trust-mask=<N> --domain=<domain>
async function cmdRun(args: string[]) {
  const { runWithKernel } = await import("./kernel/runner");

  const opts = parseRunOpts(args);
  const agentArgs = args.filter((a) => !a.startsWith("--"));

  if (agentArgs.length === 0) {
    console.error("Usage: kavachos run <agent_binary> [args] [--trust-mask=N] [--domain=D] [--dry-run] [--verbose]");
    process.exit(1);
  }

  try {
    const result = await runWithKernel(agentArgs, opts);
    if (opts.dryRun) return;
    if (result.exitCode !== 0) process.exit(result.exitCode);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`[kavachos] run failed: ${message}`);
    process.exit(1);
  }
}

// kavachos generate --trust-mask=<N> --domain=<domain> [--out=file]
async function cmdGenerate(args: string[]) {
  const { generateOnly } = await import("./kernel/runner");
  const { profileSummary } = await import("./kernel/seccomp-profile-generator");

  const trustMask = parseTrustMask(args);
  const domain = parseDomain(args);
  const outFlag = args.find((a) => a.startsWith("--out="))?.split("=")[1];
  const jsonFlag = args.includes("--json");
  const agentType = args.find((a) => a.startsWith("--agent-type="))?.split("=")[1] ?? "claude-code";

  const result = generateOnly(trustMask, domain, agentType);

  if (jsonFlag) {
    console.log(JSON.stringify(result.profile, null, 2));
  } else {
    console.log(profileSummary(result));
    console.log(`\n  trust_mask: 0x${trustMask.toString(16).padStart(8, "0")}`);
    console.log(`  syscalls:   ${result.syscall_count}`);
    console.log(`  hash:       ${result.hash}`);
    console.log(`\nFalco rules: ${result.falcoRules.rule_count} rules for domain '${domain}'`);
  }

  if (outFlag) {
    const { writeFileSync } = await import("fs");
    writeFileSync(outFile(outFlag, "seccomp.json"), JSON.stringify(result.profile, null, 2));
    writeFileSync(outFile(outFlag, "falco.yaml"), result.falcoRules.rules);
    console.log(`\nWritten: ${outFile(outFlag, "seccomp.json")} + ${outFile(outFlag, "falco.yaml")}`);
  }
}

// kavachos audit [session-id | --all]
async function cmdAudit(args: string[]) {
  const { auditSession, listSessions, printAudit } = await import("./kernel/audit");

  const listAll = args.includes("--all") || args.length === 0;

  if (listAll) {
    const sessions = listSessions();
    if (sessions.length === 0) {
      console.log("No kernel-governed sessions found in aegis.db");
      return;
    }
    console.log(`\nKavachOS governed sessions (${sessions.length}):\n`);
    for (const s of sessions) {
      const result = auditSession(s.session_id);
      const icon = result.verdict === "CLEAN" ? "✅" : "❌";
      console.log(`${icon} ${s.session_id.padEnd(28)} domain=${s.domain.padEnd(12)} trust=0x${s.trust_mask.toString(16).padStart(8,"0")} syscalls=${s.syscall_count} chain=${result.chain_valid ? "ok" : "BROKEN"}`);
    }
    return;
  }

  const sessionId = args.find((a) => !a.startsWith("--")) ?? "";
  if (!sessionId) {
    console.error("Usage: kavachos audit <session-id> | --all");
    process.exit(1);
  }

  const result = auditSession(sessionId);
  printAudit(result);
  if (result.verdict !== "CLEAN") process.exit(1);
}

// kavachos rules --domain=<domain> --trust-mask=<N> [--json]
async function cmdRules(args: string[]) {
  const { generateFalcoRules } = await import("./kernel/falco-rule-generator");

  const domain = parseDomain(args);
  const trustMask = parseTrustMask(args);
  const jsonFlag = args.includes("--json");

  const rules = generateFalcoRules(domain, trustMask);

  if (jsonFlag) {
    console.log(JSON.stringify(rules, null, 2));
  } else {
    console.log(`# KavachOS Falco Rules — domain=${domain} trust_mask=0x${trustMask.toString(16).padStart(8,"0")}`);
    console.log(`# Generated: ${rules.generated_at} | Rules: ${rules.rule_count}\n`);
    console.log(rules.rules);
  }
}

// kavachos profile show <agent-id> [--session <session-id>] [--json]
// @rule:KOS-031 display active seccomp profile + current gate valve state
async function cmdProfileShow(args: string[]) {
  const { getProfileForAgent } = await import("./kernel/profile-store");
  const { listSessions } = await import("./kernel/audit");

  const jsonFlag = args.includes("--json");
  const sessionFlag = args.find((a) => a.startsWith("--session="))?.split("=")[1]
    ?? args[args.indexOf("--session") + 1];
  const agentId = args.find((a) => !a.startsWith("--")) ?? null;

  if (!agentId) {
    // No agent-id: list all sessions with profile hashes
    const sessions = listSessions();
    if (sessions.length === 0) {
      console.log("No governed sessions found in aegis.db");
      return;
    }
    if (jsonFlag) {
      console.log(JSON.stringify(sessions, null, 2));
    } else {
      console.log(`\nKavachOS profiles (${sessions.length} sessions):\n`);
      for (const s of sessions) {
        console.log(
          `  ${s.session_id.padEnd(28)}  domain=${s.domain.padEnd(12)}` +
          `  trust=0x${s.trust_mask.toString(16).padStart(8, "0")}` +
          `  syscalls=${s.syscall_count}  hash=${s.profile_hash?.slice(0, 12) ?? "n/a"}...`
        );
      }
    }
    return;
  }

  const profile = getProfileForAgent(agentId, sessionFlag ?? null);
  if (!profile) {
    console.error(`No profile found for agent-id="${agentId}"${sessionFlag ? ` session="${sessionFlag}"` : ""}`);
    process.exit(1);
  }

  // Gate valve state from aegis.db — readValve returns a default OPEN record if not found
  const { readValve } = await import("./kavach/gate-valve");
  const valveState = readValve(agentId);

  if (jsonFlag) {
    console.log(JSON.stringify({ profile, valve_state: valveState }, null, 2));
    return;
  }

  const kv = profile._kavachos ?? {};
  console.log(`\nKavachOS Profile — agent: ${agentId}`);
  console.log(`  session_id:   ${profile._session_id ?? sessionFlag ?? "n/a"}`);
  console.log(`  domain:       ${kv.domain ?? "n/a"}`);
  console.log(`  trust_mask:   0x${(kv.trust_mask ?? 0).toString(16).padStart(8, "0")}`);
  console.log(`  syscalls:     ${profile.syscalls?.[0]?.names?.length ?? 0}`);
  console.log(`  k_seal:       ${kv.k_seal ?? "n/a"}`);
  console.log(`  generated_at: ${kv.generated_at ?? "n/a"}`);
  console.log(`  default:      ${profile.defaultAction}`);
  console.log(`\nGate valve state:`);
  const icon = valveState.state === "OPEN" ? "✅" : valveState.state === "THROTTLED" ? "⚠️" : valveState.state === "CRACKED" ? "🟠" : "🔴";
  console.log(`  ${icon} ${valveState.state}  violations=${valveState.violation_count}  reason="${valveState.narrowed_reason ?? "none"}"`);
  if (valveState.state !== "OPEN") {
    console.log(`  narrowed_at: ${valveState.narrowed_at ?? "n/a"}  locked_by: ${valveState.locked_by ?? "n/a"}`);
  }
}

// kavachos init [--domain=<d>] [--trust-mask=<N>] [--agent-type=<t>] [--force]
// @rule:KOS-033 write .kavachos.json in project root, register agent types + domains
async function cmdInit(args: string[]) {
  const { existsSync, writeFileSync } = await import("fs");
  const { resolve } = await import("path");

  const configPath = resolve(process.cwd(), ".kavachos.json");
  const force = args.includes("--force");

  if (existsSync(configPath) && !force) {
    console.error(`.kavachos.json already exists (use --force to overwrite): ${configPath}`);
    process.exit(1);
  }

  const domain = parseDomain(args);
  const trustMask = parseTrustMask(args);
  const agentType = args.find((a) => a.startsWith("--agent-type="))?.split("=")[1] ?? "claude-code";

  const config = {
    kavachos_version: "2.0.0",
    schema: "kavachos-config-v1",
    project: {
      name: resolve(process.cwd()).split("/").pop() ?? "unnamed",
      domain,
    },
    agents: [
      {
        id: agentType,
        type: agentType,
        trust_mask: trustMask,
        domain,
        description: `Default agent for ${domain} domain`,
      },
    ],
    enforcement: {
      default_action: "SCMP_ACT_ERRNO",
      falco_enabled: false,
      verbose: false,
    },
    xshieldai: {
      posture_suite: "KavachOS",
      homepage: "https://kavachos.xshieldai.com",
      license: "AGPL-3.0",
    },
    _generated_at: new Date().toISOString(),
    _rule_ref: "KOS-033",
  };

  writeFileSync(configPath, JSON.stringify(config, null, 2));
  console.log(`\nKavachOS initialized: ${configPath}`);
  console.log(`  domain:     ${domain}`);
  console.log(`  trust_mask: 0x${trustMask.toString(16).padStart(8, "0")}`);
  console.log(`  agent_type: ${agentType}`);
  console.log(`\nNext: kavachos run <your-agent> --domain=${domain} --trust-mask=0x${trustMask.toString(16)}`);
  console.log(`      kavachos profile show  (after first run)`);
}

// --- option parsers ---

function parseRunOpts(args: string[]) {
  return {
    trustMask: parseTrustMask(args),
    domain: parseDomain(args),
    agentType: args.find((a) => a.startsWith("--agent-type="))?.split("=")[1] ?? "claude-code",
    sessionId: args.find((a) => a.startsWith("--session-id="))?.split("=")[1],
    agentId: args.find((a) => a.startsWith("--agent-id="))?.split("=")[1],
    dryRun: args.includes("--dry-run"),
    verbose: args.includes("--verbose") || args.includes("-v"),
    falcoEnabled: args.includes("--falco"),
  };
}

function parseTrustMask(args: string[]): number {
  const flag = args.find((a) => a.startsWith("--trust-mask="));
  if (!flag) {
    // @rule:INF-KOS-007 absent --domain → trust_mask=1 minimal profile
    return parseInt(process.env.KAVACHOS_TRUST_MASK ?? "1", 10);
  }
  const val = flag.split("=")[1];
  return val.startsWith("0x") ? parseInt(val, 16) : parseInt(val, 10);
}

function parseDomain(args: string[]): string {
  return args.find((a) => a.startsWith("--domain="))?.split("=")[1] ?? process.env.KAVACHOS_DOMAIN ?? "general";
}

function outFile(base: string, ext: string): string {
  return base.includes(".") ? `${base.replace(/\.[^.]+$/, "")}.${ext}` : `${base}.${ext}`;
}

function printHelp() {
  console.log(`
kavachos — KavachOS kernel enforcement CLI
Part of the xShieldAI Posture Suite · kavachos.xshieldai.com
Version 2.0.0 | AGPL-3.0 | DOI 10.5281/zenodo.19908430

Usage: kavachos <command> [options]

Commands:
  run <binary> [args]        Launch agent under seccomp-bpf governance (KOS-011)
  generate                   Generate seccomp profile + Falco rules without exec
  profile show [agent-id]    Show active seccomp profile + gate valve state (KOS-031)
  audit [session-id]         Verify profile hash + PRAMANA receipt chain (KOS-012)
  rules                      Print domain-specific Falco rules
  init                       Write .kavachos.json config in project root (KOS-033)
  version                    Print version

Options for run / generate:
  --trust-mask=<N>           trust_mask value (hex or decimal, default: 1)
  --domain=<name>            Domain: general|maritime|logistics|ot|finance (default: general)
  --agent-type=<name>        Agent type label (default: claude-code)
  --session-id=<id>          Override session ID
  --agent-id=<id>            Agent ID for receipt chain linkage
  --falco                    Write Falco rules file alongside seccomp profile
  --dry-run                  Generate profile only, do not exec
  --verbose / -v             Verbose kernel messages on stderr
  --json                     Output JSON (generate/rules/audit/profile)
  --out=<path>               Write profile + rules to files (generate only)

Options for audit / profile show:
  --all                      List all sessions (audit) / all profiles (profile show)
  --session=<id>             Filter profile show by session ID

Options for init:
  --force                    Overwrite existing .kavachos.json

Examples:
  kavachos init --domain=maritime --trust-mask=0xFF
  kavachos run claude --trust-mask=0xFF --domain=general --verbose
  kavachos run bun src/my-agent.ts --trust-mask=0x00FF0000 --domain=maritime --falco
  kavachos generate --trust-mask=255 --domain=logistics --json
  kavachos generate --trust-mask=0 --domain=general --out=/tmp/minimal
  kavachos profile show agent-123
  kavachos profile show
  kavachos audit KOS-A1B2C3
  kavachos audit --all
  kavachos rules --domain=maritime --trust-mask=0x0000FF00

Rules:
  KOS-011: This CLI is the only approved path for governed agent launch
  KOS-010: Profiles are generated deterministically — never hand-written
  KOS-012: Profile drift = security incident
  KOS-031: profile show = live posture view for any governed agent
  KOS-033: init = project-level config, registers agent types + domains
  INF-KOS-001: trust_mask=0 → read-only minimal profile
  INF-KOS-007: --domain absent → trust_mask=1 → minimal safe profile
`);
}

main().catch((err) => {
  const message = err instanceof Error ? err.message : String(err);
  console.error(`kavachos error: ${message}`);
  process.exit(1);
});
