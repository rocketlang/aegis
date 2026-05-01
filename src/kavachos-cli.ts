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
//   sessions [list]              List all registered Claude Code sessions (KOS-076/077/078)
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
    case "egress":
      if (subCommand === "show") return cmdEgressShow(Bun.argv.slice(4));
      console.error(`Unknown egress sub-command: ${subCommand}. Try: kavachos egress show [session-id]`);
      process.exit(1);
      break;
    case "proxy":
      if (subCommand === "start") return cmdProxyStart(Bun.argv.slice(4));
      if (subCommand === "cert") return cmdProxyCert();
      console.error(`Unknown proxy sub-command: ${subCommand}. Try: kavachos proxy start [--port=4856] [--upstream=https://api.anthropic.com]`);
      process.exit(1);
      break;
    case "sessions":
      return cmdSessions(args);
    case "report":
      return cmdReport(args);
    case "audit":
      return cmdAudit(args);
    case "verify-chain":
      return cmdVerifyChain(args);
    case "checkpoint":
      return cmdCheckpoint(args);
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
  const delegationDepth = parseDelegationDepth(args);  // @rule:KOS-092
  const outFlag = args.find((a) => a.startsWith("--out="))?.split("=")[1];
  const jsonFlag = args.includes("--json");
  const agentType = args.find((a) => a.startsWith("--agent-type="))?.split("=")[1] ?? "claude-code";

  const result = generateOnly(trustMask, domain, agentType, delegationDepth);

  if (jsonFlag) {
    console.log(JSON.stringify(result.profile, null, 2));
  } else {
    console.log(profileSummary(result));
    console.log(`\n  trust_mask: 0x${trustMask.toString(16).padStart(8, "0")}`);
    console.log(`  depth:      ${delegationDepth}`);
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

// kavachos verify-chain [--session <id>] [--all] [--json]
// @rule:KOS-T042 re-walk PRAMANA SHA-256 chain; verify inclusion in Merkle checkpoint
async function cmdVerifyChain(args: string[]) {
  const { verifyReceiptChain } = await import("./kernel/merkle-ledger");
  const { getDb } = await import("./core/db");

  const jsonOut = args.includes("--json");
  const all = args.includes("--all");
  const sessionArg = args.find(a => !a.startsWith("--") && a !== "verify-chain");

  if (all || !sessionArg) {
    const db = getDb();
    const sessions = db.prepare(
      "SELECT DISTINCT session_id FROM kernel_receipts ORDER BY session_id"
    ).all() as Array<{ session_id: string }>;

    if (sessions.length === 0) {
      console.log("No receipt chains found in aegis.db");
      return;
    }

    const results = sessions.map(s => verifyReceiptChain(s.session_id));
    if (jsonOut) { console.log(JSON.stringify(results, null, 2)); return; }

    console.log(`\nPRAMANA receipt chain verification (${results.length} sessions):\n`);
    for (const r of results) {
      const icon = r.valid ? "✅" : "❌";
      const merkle = r.included_in_merkle ? ` Merkle:${r.checkpoint_id}` : r.included_in_merkle === false ? " Merkle:not_yet_checkpointed" : "";
      console.log(`${icon} ${r.session_id.padEnd(32)} receipts=${r.receipt_count}${merkle}`);
      if (!r.valid) console.log(`   ⚠️  broken at ${r.broken_at_receipt}: ${r.broken_reason}`);
    }
    return;
  }

  const result = verifyReceiptChain(sessionArg);
  if (jsonOut) { console.log(JSON.stringify(result, null, 2)); return; }

  if (result.valid) {
    console.log(`\n✅ Chain valid — session: ${result.session_id}`);
    console.log(`   receipts: ${result.receipt_count}`);
    if (result.checkpoint_id) {
      console.log(`   Merkle checkpoint: ${result.checkpoint_id}`);
      console.log(`   included_in_merkle: ${result.included_in_merkle}`);
    } else {
      console.log(`   not yet included in a Merkle checkpoint`);
    }
  } else {
    console.error(`\n❌ Chain BROKEN — session: ${result.session_id}`);
    console.error(`   broken at: ${result.broken_at_receipt}`);
    console.error(`   reason: ${result.broken_reason}`);
    process.exit(1);
  }
}

// kavachos sessions [list] [--limit=N] [--json] [--active]
// @rule:KOS-076 session registry — registered by UserPromptSubmit hook at first prompt
// @rule:KOS-077 per-session JSONL activity log — appended by PostToolUse hook
// @rule:KOS-078 session summary written at Stop hook — duration + DAN count + cost
async function cmdSessions(args: string[]) {
  const { existsSync, readdirSync, readFileSync } = await import("fs");
  const { join } = await import("path");
  const { getAegisDir } = await import("./core/config");
  const { getDb } = await import("./core/db");

  const sub = args[0] ?? "list";
  const jsonOut = args.includes("--json");
  const limitArg = parseInt(args.find(a => a.startsWith("--limit="))?.split("=")[1] ?? "50");
  const activeOnly = args.includes("--active");

  if (sub !== "list" && sub !== undefined) {
    // treat as session-id lookup
  }

  const sessionsDir = join(getAegisDir(), "sessions");
  if (!existsSync(sessionsDir)) {
    console.log("No sessions captured yet. UserPromptSubmit hook registers sessions on first prompt.");
    return;
  }

  // Pull from DB for structured data
  let rows: Array<Record<string, unknown>> = [];
  try {
    const db = getDb();
    const where = activeOnly ? `WHERE status='active'` : "";
    rows = db.prepare(
      `SELECT session_id, status, hostname, model, git_remote, project_path,
              first_seen, last_activity, ended_at, stop_reason,
              tool_call_count, dan_event_count, total_cost_usd, mudrika_uri
       FROM sessions ${where}
       ORDER BY COALESCE(last_activity, first_seen) DESC
       LIMIT ?`
    ).all(limitArg) as Array<Record<string, unknown>>;
  } catch {
    // DB may not have new columns yet — fall back to desk files
  }

  // Supplement with desk files for sessions not yet in DB
  const deskFiles = readdirSync(sessionsDir).filter(f => f.endsWith(".desk.json"));
  const dbIds = new Set(rows.map(r => r.session_id as string));

  for (const f of deskFiles.slice(0, limitArg)) {
    try {
      const desk = JSON.parse(readFileSync(join(sessionsDir, f), "utf-8"));
      if (dbIds.has(desk.session_id)) continue;

      // Check for summary file (Stop hook fired)
      const summaryPath = join(sessionsDir, `${desk.session_id}.summary.json`);
      let summary: Record<string, unknown> = {};
      if (existsSync(summaryPath)) {
        try { summary = JSON.parse(readFileSync(summaryPath, "utf-8")); } catch {}
      }

      // Count JSONL lines
      const jsonlPath = join(sessionsDir, `${desk.session_id}.jsonl`);
      let toolCalls = 0;
      if (existsSync(jsonlPath)) {
        try {
          toolCalls = readFileSync(jsonlPath, "utf-8").split("\n").filter(l => l.trim()).length;
        } catch {}
      }

      rows.push({
        session_id: desk.session_id,
        status: summary.stop_reason ? "completed" : "active",
        hostname: desk.hostname,
        model: desk.model,
        git_remote: desk.git_remote,
        project_path: desk.cwd,
        first_seen: desk.registered_at,
        last_activity: null,
        ended_at: summary.ended_at ?? null,
        stop_reason: summary.stop_reason ?? null,
        tool_call_count: toolCalls,
        dan_event_count: summary.dan_event_count ?? 0,
        total_cost_usd: summary.total_cost_usd ?? 0,
        mudrika_uri: null,
      });
    } catch { /* skip */ }
  }

  if (jsonOut) {
    console.log(JSON.stringify(rows, null, 2));
    return;
  }

  if (rows.length === 0) {
    console.log("No sessions found.");
    return;
  }

  console.log(`\nKavachOS session registry (${rows.length} sessions):\n`);
  console.log(
    "  SESSION ID".padEnd(32) +
    "STATUS".padEnd(12) +
    "HOST".padEnd(18) +
    "MODEL".padEnd(20) +
    "TOOLS".padEnd(8) +
    "DAN".padEnd(6) +
    "COST".padEnd(10) +
    "STARTED"
  );
  console.log("  " + "─".repeat(118));

  for (const r of rows) {
    const sid = (r.session_id as string ?? "").slice(0, 28);
    const status = (r.status as string ?? "unknown").padEnd(10);
    const host = ((r.hostname as string ?? "?").slice(0, 16)).padEnd(18);
    const model = ((r.model as string ?? "?").slice(0, 18)).padEnd(20);
    const tools = String(r.tool_call_count ?? 0).padEnd(8);
    const dan = String(r.dan_event_count ?? 0).padEnd(6);
    const cost = `$${Number(r.total_cost_usd ?? 0).toFixed(4)}`.padEnd(10);
    const started = (r.first_seen as string ?? "").slice(0, 19).replace("T", " ");
    const icon = (r.status as string) === "completed" ? "✅" : (r.status as string) === "active" ? "🟢" : "⚪";
    console.log(`  ${icon} ${sid.padEnd(30)} ${status} ${host} ${model} ${tools} ${dan} ${cost} ${started}`);
  }

  const totalCost = rows.reduce((s, r) => s + Number(r.total_cost_usd ?? 0), 0);
  const totalTools = rows.reduce((s, r) => s + Number(r.tool_call_count ?? 0), 0);
  const totalDan = rows.reduce((s, r) => s + Number(r.dan_event_count ?? 0), 0);
  console.log("\n  " + "─".repeat(118));
  console.log(`  Totals: ${rows.length} sessions | ${totalTools} tool calls | ${totalDan} DAN events | $${totalCost.toFixed(4)} spend`);
  console.log(`\n  Desk files:   ${join(getAegisDir(), "sessions")}/*.desk.json`);
  console.log(`  Activity:     ${join(getAegisDir(), "sessions")}/*.jsonl`);
  console.log(`  Summaries:    ${join(getAegisDir(), "sessions")}/*.summary.json\n`);
}

// kavachos report [--standard=eu-ai-act|rbi|dpdp|all] [--period=30d] [--output=path] [--quiet]
// @rule:KOS-073 compliance evidence package generator
async function cmdReport(args: string[]) {
  const { runReportCommand } = await import("./compliance/report-generator");
  runReportCommand(args);
}

// kavachos checkpoint [run | list] [--json]
// @rule:KOS-T040 create / list Merkle checkpoints
async function cmdCheckpoint(args: string[]) {
  const { runHourlyCheckpoint, listCheckpoints, verifySthSignature } = await import("./kernel/merkle-ledger");
  const { anchorCheckpoint } = await import("./kernel/merkle-anchor");

  const sub = args[0] ?? "list";
  const jsonOut = args.includes("--json");

  if (sub === "run") {
    const hours = parseInt(args.find(a => a.startsWith("--hours="))?.split("=")[1] ?? "1");
    const cp = await runHourlyCheckpoint(hours);
    if (!cp) {
      console.log("No receipts in period — checkpoint not created.");
      return;
    }
    const anchor = await anchorCheckpoint(cp);
    if (jsonOut) { console.log(JSON.stringify({ checkpoint: cp, anchor }, null, 2)); return; }
    console.log(`\n✅ Merkle checkpoint created`);
    console.log(`   ID:       ${cp.checkpoint_id}`);
    console.log(`   leaves:   ${cp.tree_size}`);
    console.log(`   root:     ${cp.sha256_root_hash}`);
    console.log(`   anchored: ${anchor.ref} (${anchor.method})`);
    return;
  }

  if (sub === "list" || sub === undefined) {
    const limit = parseInt(args.find(a => a.startsWith("--limit="))?.split("=")[1] ?? "20");
    const checkpoints = listCheckpoints(limit);
    if (jsonOut) { console.log(JSON.stringify(checkpoints, null, 2)); return; }
    if (checkpoints.length === 0) { console.log("No checkpoints yet. Run: kavachos checkpoint run"); return; }
    console.log(`\nMerkle checkpoints (${checkpoints.length}):\n`);
    for (const cp of checkpoints) {
      const sigValid = verifySthSignature(
        JSON.stringify({ checkpoint_id: cp.checkpoint_id, tree_size: cp.tree_size, sha256_root_hash: cp.sha256_root_hash, period_start: cp.period_start, period_end: cp.period_end, pramana_version: "1.1" }),
        cp.signature, cp.public_key_hex
      );
      console.log(`  ${cp.checkpoint_id}`);
      console.log(`    root:    ${cp.sha256_root_hash}`);
      console.log(`    leaves:  ${cp.tree_size}   sig: ${sigValid ? "✅ valid" : "❌ INVALID"}`);
    }
    return;
  }

  console.error(`Unknown sub-command: ${sub}. Try: kavachos checkpoint run | list`);
  process.exit(1);
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

// kavachos egress show [session-id] — show active egress policy for a session
// @rule:KOS-042 egress allowlist declared at launch — this command makes it visible
// @rule:KOS-YK-006 operator must be able to see what egress is active without root
async function cmdEgressShow(args: string[]) {
  const { existsSync, readdirSync, readFileSync } = await import("fs");
  const { join } = await import("path");
  const { getAegisDir } = await import("./core/config");

  const sessionId = args.find((a) => !a.startsWith("--")) ?? null;
  const jsonFlag = args.includes("--json");
  const KAVACHOS_DIR = join(getAegisDir(), "kernel");

  if (!existsSync(KAVACHOS_DIR)) {
    console.error(`No kernel session data found at ${KAVACHOS_DIR}`);
    process.exit(1);
  }

  const allFiles = readdirSync(KAVACHOS_DIR);
  const egressFiles = allFiles
    .filter((f) => f.endsWith(".egress.json"))
    .filter((f) => sessionId ? f.startsWith(sessionId) : true);

  if (egressFiles.length === 0) {
    console.error(sessionId
      ? `No egress policy found for session: ${sessionId}`
      : "No egress policy files found. Run kavachos with egress enabled.");
    process.exit(1);
  }

  const policies: Array<{ session: string; policy: ReturnType<typeof JSON.parse> }> = [];
  for (const file of egressFiles.sort().reverse()) {
    const sid = file.replace(".egress.json", "");
    try {
      const raw = readFileSync(join(KAVACHOS_DIR, file), "utf-8");
      policies.push({ session: sid, policy: JSON.parse(raw) });
    } catch {
      // skip corrupt files
    }
  }

  if (jsonFlag) {
    console.log(JSON.stringify(policies, null, 2));
    return;
  }

  for (const { session, policy } of policies) {
    console.log(`\nEgress policy — session: ${session}`);
    console.log(`  domain:     ${policy.domain ?? "unknown"}`);
    console.log(`  trust_mask: 0x${(policy.trust_mask ?? 0).toString(16).padStart(8, "0")}`);
    console.log(`  allow entries: ${policy.allow?.length ?? 0}`);
    console.log(`\n  Host allowlist:`);
    for (const entry of (policy.allow ?? [])) {
      const port = entry.port === 0 ? "any" : String(entry.port);
      console.log(`    ${entry.host.padEnd(40)} :${port.padEnd(6)} ${entry.note ?? ""}`);
    }
  }
}

// kavachos proxy start [--port=4856] [--upstream=URL] [--domain=<d>] [--verbose]
// @rule:KOS-050 TLS proxy — inspects LLM API traffic before it reaches the upstream
// @rule:KOS-051 zero agent code change — set KAVACHOS_PROXY_URL, kavachos run injects base URL overrides
async function cmdProxyStart(args: string[]) {
  const { startProxy } = await import("./proxy/kavachos-proxy");

  const port = parseInt(
    args.find((a) => a.startsWith("--port="))?.split("=")[1] ?? "4856",
    10
  );
  const upstream =
    args.find((a) => a.startsWith("--upstream="))?.split("=")[1] ??
    process.env.KAVACHOS_PROXY_UPSTREAM ??
    "https://api.anthropic.com";
  const domain = parseDomain(args);
  const sessionId = args.find((a) => a.startsWith("--session-id="))?.split("=")[1] ??
    process.env.KAVACHOS_SESSION_ID;
  const verbose = args.includes("--verbose") || args.includes("-v");

  await startProxy({ port, upstream, domain, sessionId, verbose });
  // startProxy calls Bun.serve (non-blocking) then logs ready.
  // Keep the process alive.
  await new Promise(() => {});
}

// kavachos proxy cert — print the self-signed CA cert so operators can trust it
async function cmdProxyCert() {
  const { existsSync, readFileSync } = await import("fs");
  const certPath = "/tmp/kavachos-proxy.crt";
  if (!existsSync(certPath)) {
    console.error("No cert found. Start the proxy first: kavachos proxy start");
    process.exit(1);
  }
  console.log(readFileSync(certPath, "utf-8").trim());
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
    delegationDepth: parseDelegationDepth(args),  // @rule:KOS-092
    dryRun: args.includes("--dry-run"),
    verbose: args.includes("--verbose") || args.includes("-v"),
    falcoEnabled: args.includes("--falco"),
    strictExec: args.includes("--strict-exec"),
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

function parseDelegationDepth(args: string[]): number {
  const flag = args.find((a) => a.startsWith("--depth="));
  if (!flag) return parseInt(process.env.KAVACHOS_DELEGATION_DEPTH ?? "1", 10);
  return parseInt(flag.split("=")[1], 10);
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
  egress show [session-id]   Show active egress policy (host allowlist) for a session (KOS-042)
  proxy start                Start L7 TLS-terminating proxy on port 4856 (KOS-050)
  proxy cert                 Print self-signed CA cert for agent trust configuration
  sessions [list]            List all registered Claude Code sessions, desk + activity (KOS-076/077/078)
  audit [session-id]         Verify profile hash + PRAMANA receipt chain (KOS-012)
  verify-chain [--session]   Re-walk SHA-256 receipt chain + Merkle inclusion check (KOS-T042)
  checkpoint run|list        Create/list Merkle STH checkpoints (KOS-T040)
  report                     Generate EU AI Act / RBI / DPDP compliance evidence package (KOS-073)
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
  --strict-exec              Gate execve/execveat — auto-ALLOW/DENY from exec allowlist (KOS-046)
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
  kavachos egress show
  kavachos egress show KOS-A1B2C3
  kavachos egress show --json
  kavachos proxy start --upstream=https://api.anthropic.com --domain=general
  kavachos proxy start --port=4856 --upstream=https://api.openai.com --verbose
  kavachos proxy cert   # print CA cert for NODE_EXTRA_CA_CERTS
  kavachos audit KOS-A1B2C3
  kavachos audit --all
  kavachos rules --domain=maritime --trust-mask=0x0000FF00
  kavachos run bun src/agent.ts --strict-exec --trust-mask=0xFF --domain=general

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
