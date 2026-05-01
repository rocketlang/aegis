// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// @rule:KOS-011 kavachos run — only approved agent launch path

import { writeFileSync, mkdirSync, existsSync, unlinkSync } from "fs";
import { join, dirname } from "path";
import { spawn } from "child_process";
import { randomBytes } from "crypto";
import { generateSeccompProfile, profileSummary } from "./seccomp-profile-generator";
import { generateFalcoRules } from "./falco-rule-generator";
import { storeProfile, checkProfileDrift } from "./profile-store";
import { sealKernelViolation, parseFalcoEvent, checkViolationRate } from "./kernel-receipt";
import { buildEgressPolicy, serialiseEgressPolicy } from "./egress-policy";
import { buildExecAllowlist, serialiseExecAllowlist } from "./exec-allowlist";
import { getAegisDir } from "../core/config";
import { addAlert } from "../core/db";

export interface RunOptions {
  trustMask: number;
  domain: string;
  agentType?: string;
  sessionId?: string;
  agentId?: string;
  delegationDepth?: number; // @rule:KOS-092 — depth drives seccomp reduction schedule
  hilRequired?: boolean;    // @rule:KOS-096 — explicit HIL flag (from SDT human_in_loop_required)
  dryRun?: boolean;         // generate profile only, do not exec
  verbose?: boolean;
  falcoEnabled?: boolean;   // emit Falco rules file (requires Falco installed)
  egressEnabled?: boolean;  // @rule:KOS-040 cgroup BPF egress firewall (Phase 1E)
  strictExec?: boolean;     // @rule:KOS-046 exec allowlist — execve/execveat gated
}

export interface RunResult {
  sessionId: string;
  profileHash: string;
  syscallCount: number;
  profilePath: string;
  falcoRulesPath: string | null;
  egressPolicyPath: string | null;
  pid?: number;
  exitCode?: number;
}

const APPLY_SECCOMP_PY = join(dirname(new URL(import.meta.url).pathname), "apply-seccomp.py");
const KAVACHOS_DIR = join(getAegisDir(), "kernel");

function ensureKavachosDir(): void {
  if (!existsSync(KAVACHOS_DIR)) mkdirSync(KAVACHOS_DIR, { recursive: true });
}

// @rule:KOS-011 the only approved path for governed agent launch
export async function runWithKernel(
  agentCommand: string[],
  opts: RunOptions
): Promise<RunResult> {
  ensureKavachosDir();

  const sessionId = opts.sessionId ?? `KOS-${randomBytes(6).toString("hex").toUpperCase()}`;
  const agentType = opts.agentType ?? "claude-code";

  const strictExec = opts.strictExec ?? false;
  const delegationDepth = opts.delegationDepth ?? 1;
  const hilRequired = opts.hilRequired ?? (delegationDepth >= 4); // @rule:KOS-096

  // @rule:KOS-096 emit alert before launch so dashboard shows HIL gate immediately
  if (hilRequired) {
    try {
      addAlert({
        type: "delegation_hil_required",
        severity: "warning",
        message: `Agent ${opts.agentId ?? sessionId} running at delegation depth ${delegationDepth} — all writes supervisor-gated (KOS-096)`,
        session_id: sessionId,
        timestamp: new Date().toISOString(),
        acknowledged: false,
      });
    } catch { /* dashboard db unavailable — CLI mode */ }
  }

  // 1. Generate seccomp profile (KOS-010 — deterministic; KOS-092 — depth-graduated)
  const { profile, hash: profileHash, syscall_count } = generateSeccompProfile(
    opts.trustMask,
    opts.domain,
    agentType,
    strictExec,
    delegationDepth
  );

  if (opts.verbose) {
    console.error(profileSummary({ profile, hash: profileHash, syscall_count }));
  }

  // 2. Write profile to temp file
  const profilePath = join(KAVACHOS_DIR, `${sessionId}.seccomp.json`);
  writeFileSync(profilePath, JSON.stringify(profile, null, 2));

  // 3. Store profile + hash in aegis.db (KOS-012 — drift detection)
  storeProfile(sessionId, opts.agentId ?? null, profile, profilePath);

  // 4. Generate Falco rules (KOS-013 — domain-specific)
  let falcoRulesPath: string | null = null;
  if (opts.falcoEnabled) {
    const falcoRules = generateFalcoRules(opts.domain, opts.trustMask);
    falcoRulesPath = join(KAVACHOS_DIR, `${sessionId}.falco.yaml`);
    writeFileSync(falcoRulesPath, falcoRules.rules);
    if (opts.verbose) {
      console.error(`[kavachos] Falco rules written: ${falcoRulesPath} (${falcoRules.rule_count} rules)`);
    }
  }

  // 4B. Write exec allowlist (Phase 1F — KOS-046) when strict_exec active
  // @rule:KOS-047 written at launch; supervisor reads it for auto-ALLOW/DENY
  let execAllowlistPath: string | null = null;
  if (strictExec) {
    const execAllowlist = buildExecAllowlist(agentType, true);
    execAllowlistPath = join(KAVACHOS_DIR, `${sessionId}.exec-allowlist.json`);
    writeFileSync(execAllowlistPath, serialiseExecAllowlist(execAllowlist));
    if (opts.verbose) {
      console.error(`[kavachos] Exec allowlist written: ${execAllowlistPath} (${execAllowlist.allow.length} entries)`);
    }
  }

  // 4C. Write egress policy (Phase 1E — KOS-040)
  // @rule:KOS-043 written at launch, never updated after agent starts
  let egressPolicyPath: string | null = null;
  if (opts.egressEnabled !== false) {  // enabled by default
    const egressPolicy = buildEgressPolicy(opts.trustMask, opts.domain);
    egressPolicyPath = join(KAVACHOS_DIR, `${sessionId}.egress.json`);
    writeFileSync(egressPolicyPath, serialiseEgressPolicy(egressPolicy));
    if (opts.verbose) {
      console.error(`[kavachos] Egress policy written: ${egressPolicyPath} (${egressPolicy.allow.length} hosts)`);
    }
  }

  if (opts.dryRun) {
    console.log(JSON.stringify({
      sessionId,
      profileHash,
      syscallCount: syscall_count,
      profilePath,
      falcoRulesPath,
      egressPolicyPath,
      dryRun: true,
    }, null, 2));
    return { sessionId, profileHash, syscallCount: syscall_count, profilePath, falcoRulesPath, egressPolicyPath };
  }

  // 5. Launch agent via Python seccomp applicator (KOS-011, KOS-006)
  // @rule:KOS-051 zero agent code change: redirect all LLM API calls through kavachos-proxy
  // If KAVACHOS_PROXY_URL is set (proxy is running), inject base URL overrides so the agent
  // uses the proxy without any code changes. Falls back to direct API if proxy not set.
  const proxyUrl = process.env.KAVACHOS_PROXY_URL ?? null;
  const proxyEnvOverrides: NodeJS.ProcessEnv = proxyUrl ? {
    ANTHROPIC_BASE_URL:    proxyUrl,
    OPENAI_BASE_URL:       proxyUrl,
    OPENAI_API_BASE:       proxyUrl,
    GOOGLE_GENERATIVE_AI_ENDPOINT: proxyUrl,
    GROQ_BASE_URL:         proxyUrl,
    KAVACHOS_PROXY_ACTIVE: "1",
    // Allow self-signed cert (per-boot, localhost only) — @rule:KOS-050
    NODE_TLS_REJECT_UNAUTHORIZED: "0",
    PYTHONHTTPSVERIFY:     "0",
  } : {};

  const env: NodeJS.ProcessEnv = {
    ...process.env,
    KAVACHOS_SESSION_ID: sessionId,
    KAVACHOS_AGENT_ID: opts.agentId ?? sessionId,
    KAVACHOS_TRUST_MASK: opts.trustMask.toString(),
    KAVACHOS_DOMAIN: opts.domain,
    KAVACHOS_DELEGATION_DEPTH: delegationDepth.toString(),  // @rule:KOS-092
    ...(execAllowlistPath ? { KAVACHOS_EXEC_ALLOWLIST: execAllowlistPath } : {}),
    ...proxyEnvOverrides,
  };

  const launchArgs = [
    "python3",
    APPLY_SECCOMP_PY,
    profilePath,
    "--",
    ...agentCommand,
  ];

  if (opts.verbose) {
    console.error(`[kavachos] Launching: ${launchArgs.join(" ")}`);
  }

  return new Promise((resolve, reject) => {
    const child = spawn(launchArgs[0], launchArgs.slice(1), {
      stdio: ["inherit", "inherit", "pipe"],
      env,
    });

    const result: RunResult = {
      sessionId,
      profileHash,
      syscallCount: syscall_count,
      profilePath,
      falcoRulesPath,
      egressPolicyPath,
      pid: child.pid,
    };

    // Phase 1E: launch cgroup-egress.py sidecar once agent PID is known
    // @rule:KOS-040 — the sidecar creates the cgroup and attaches the BPF program
    if (egressPolicyPath && child.pid) {
      const CGROUP_EGRESS_PY = join(dirname(new URL(import.meta.url).pathname), "cgroup-egress.py");
      const egressSidecar = spawn("python3", [CGROUP_EGRESS_PY, sessionId, egressPolicyPath, String(child.pid)], {
        stdio: ["ignore", "ignore", "pipe"],
      });
      egressSidecar.stderr?.on("data", (d: Buffer) => {
        const line = d.toString().trim();
        if (line) process.stderr.write(line + "\n");
      });
      egressSidecar.on("error", (err) => {
        process.stderr.write(`[kavachos:egress] sidecar error: ${err.message}\n`);
      });
    }

    const recentReceipts: ReturnType<typeof sealKernelViolation>[] = [];

    // Monitor stderr for kavachos kernel events (SIGSYS logs, Falco-forwarded events)
    child.stderr?.on("data", (data: Buffer) => {
      const lines = data.toString().split("\n").filter(Boolean);
      for (const line of lines) {
        // Forward kavachos kernel lines to our stderr
        if (line.includes("[kavachos]")) {
          process.stderr.write(line + "\n");
        }

        // Parse Falco JSON events if present
        if (line.startsWith("{") && line.includes('"rule"')) {
          const event = parseFalcoEvent(line);
          if (event) {
            event.session_id = sessionId;
            const receipt = sealKernelViolation({ ...event, profile_hash: profileHash, delegation_depth: delegationDepth });
            recentReceipts.push(receipt);

            // @rule:INF-KOS-002 rate check
            if (checkViolationRate(recentReceipts)) {
              process.stderr.write(`[kavachos] RATE_EXCEEDED: >5 violations/min for session ${sessionId}\n`);
              sealKernelViolation({
                session_id: sessionId,
                agent_id: opts.agentId ?? null,
                event_type: "RATE_EXCEEDED",
                violation_details: "Falco violation rate exceeded 5/min — potential low-and-slow exfil",
                profile_hash: profileHash,
                severity: "CRITICAL",
                delegation_depth: delegationDepth,
              });
            }
          }
        }
      }
    });

    child.on("exit", (code: number | null) => {
      result.exitCode = code ?? 0;

      // Cleanup temp files
      try { unlinkSync(profilePath); } catch { /* already gone */ }
      if (egressPolicyPath) { try { unlinkSync(egressPolicyPath); } catch { /* ok */ } }

      // @rule:KOS-012 post-session drift check
      const drift = checkProfileDrift(sessionId);
      if (drift) {
        process.stderr.write(`[kavachos] PROFILE DRIFT DETECTED for session ${sessionId}\n`);
        sealKernelViolation({
          session_id: sessionId,
          agent_id: opts.agentId ?? null,
          event_type: "PROFILE_DRIFT",
          violation_details: `Hash mismatch: stored=${drift.stored_hash.slice(0, 16)}... actual=${drift.actual_hash.slice(0, 16)}...`,
          severity: "CRITICAL",
          delegation_depth: delegationDepth,
        });
      }

      resolve(result);
    });

    child.on("error", (err: Error) => reject(err));
  });
}

// Quick profile-only generation (no exec) — for testing and CI
export function generateOnly(trustMask: number, domain: string, agentType?: string, delegationDepth: number = 1) {
  const result = generateSeccompProfile(trustMask, domain, agentType, false, delegationDepth);
  const falcoRules = generateFalcoRules(domain, trustMask);
  return { ...result, falcoRules };
}
