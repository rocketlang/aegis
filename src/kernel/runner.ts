// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// @rule:KOS-011 kavachos run — only approved agent launch path

import { writeFileSync, mkdirSync, existsSync, unlinkSync, readFileSync } from "fs";
import { join, dirname } from "path";
import { spawn } from "child_process";
import { randomBytes } from "crypto";
import { generateSeccompProfile, profileSummary } from "./seccomp-profile-generator";
import { generateFalcoRules } from "./falco-rule-generator";
import { storeProfile, checkProfileDrift } from "./profile-store";
import { sealKernelViolation, parseFalcoEvent, checkViolationRate } from "./kernel-receipt";
import { serialiseEgressPolicy, egressLaunchDecision } from "./egress-policy";
import { compilePolicy } from "../kavach/compile-policy";
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
  /**
   * Proceed even though this host cannot enforce egress. @rule:INF-KOS-009
   *
   * Accepts ONLY the UNAVAILABLE case — a host without cgroup BPF, which an operator can
   * know in advance. It never excuses FAILED or a timeout: those say something went wrong
   * on a host that can enforce, and a fault is not a configuration.
   */
  allowUnconstrainedEgress?: boolean;
  strictExec?: boolean;     // @rule:KOS-046 exec allowlist — execve/execveat gated
  /** @rule:ANU-008 loopback ports this agent legitimately needs. Supplying them lets the
   *  compiler narrow the any-port loopback allow; without them, local denies stay advisory. */
  loopbackPorts?: number[];
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
  /** Set when the launch was REFUSED rather than attempted. @rule:INF-KOS-009 */
  refused?: string;
  /** Whether cgroup BPF egress actually armed for this session — not whether a policy
   *  was written. A launch record used to be able to show a perfect egress policy for an
   *  agent that ran with no egress control at all. */
  egressEnforced?: boolean;
}

const APPLY_SECCOMP_PY = join(dirname(new URL(import.meta.url).pathname), "apply-seccomp.py");
const KAVACHOS_DIR = join(getAegisDir(), "kernel");

// ── AppArmor path jail ────────────────────────────────────────────────────────
// seccomp filters syscalls but cannot see file PATHS. The kavachos-agent AppArmor
// profile (src/kernel/apparmor/) is the path layer: agent + every child (ix) is
// denied the AEGIS approval-signing key, mudrika secret, and /root/.ankr/secrets
// (IAM app keys — a token minted from those walks through kika-gate).
// KAVACHOS_JAIL: prefer (default — attach when loaded, CRITICAL alert when not) |
//                require (fail CLOSED: no profile → no launch) | off
// @rule:KGT-002 fail-closed key custody · @rule:KGT-006 violations train the armor
const APPARMOR_PROFILE = "kavachos-agent";

function apparmorJailMode(): "require" | "prefer" | "off" {
  const v = (process.env.KAVACHOS_JAIL ?? "prefer").toLowerCase();
  return v === "require" || v === "off" ? v : "prefer";
}

function apparmorProfileLoaded(): boolean {
  try {
    return readFileSync("/sys/kernel/security/apparmor/profiles", "utf-8")
      .split("\n")
      .some((l) => l.startsWith(`${APPARMOR_PROFILE} `));
  } catch {
    return false; // AppArmor absent (non-Linux / disabled) — prefer-mode degrades loud
  }
}

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
    // @rule:ANU-008 — the enforced allowlist is COMPILED from the fine invariants rather
    // than taken raw from the generator. The enforcer is default-deny over this map, so
    // withholding an endpoint IS the denial; the compiler decides what may be withheld.
    const compiled = compilePolicy({
      agentId: sessionId,
      domain: opts.domain,
      trustMask: opts.trustMask,
      loopbackPorts: opts.loopbackPorts ?? [],
    });
    const egressPolicy = { domain: opts.domain, trust_mask: opts.trustMask, allow: compiled.egress_allow };
    egressPolicyPath = join(KAVACHOS_DIR, `${sessionId}.egress.json`);
    writeFileSync(egressPolicyPath, serialiseEgressPolicy(egressPolicy));

    // The coarse policy is kept beside it, so what was enforced can be re-derived later.
    writeFileSync(join(KAVACHOS_DIR, `${sessionId}.coarse.json`), JSON.stringify(compiled, null, 2));

    if (opts.verbose) {
      console.error(`[kavachos] Egress policy written: ${egressPolicyPath} (${egressPolicy.allow.length} hosts)`);
      const advisory = compiled.notes.filter(n => n.kind === "conflict").length;
      const narrowed = compiled.notes.filter(n => n.kind === "substitution").length;
      console.error(
        `[kavachos:anumati] compiled — ${compiled.egress_deny.length} address(es) denied` +
          (narrowed ? `, loopback narrowed` : "") +
          (advisory ? `, ${advisory} advisory (wildcard readmits them — pass --needs)` : ""),
      );
      if (compiled.unbound_by_coarse.length) {
        console.error(
          `[kavachos:anumati] ${compiled.unbound_by_coarse.length} invariant(s) have no coarse form ` +
            `(${compiled.unbound_by_coarse.join(", ")}) — cooperative agents only`,
        );
      }
    }
  }

  // 4E. Measure what will govern this agent, from the artefacts just written, and
  // record it beside them. @rule:PRA-005 — the value is comparable against a reference
  // published with the release, which is what makes the check possible from off-host.
  try {
    const { measureLaunchFromArtefacts, renderLaunch } = await import("../kavach/measure-launch");
    const m = measureLaunchFromArtefacts(
      {
        profilePath,
        execAllowlistPath: execAllowlistPath ?? null,
        coarsePath: join(KAVACHOS_DIR, `${sessionId}.coarse.json`),
      },
      {
        trust_mask: opts.trustMask,
        domain: opts.domain,
        agent_type: opts.agentType ?? "claude-code",
        strict_exec: opts.strictExec ?? false,
        delegation_depth: delegationDepth,
      },
    );
    if ("error" in m) {
      console.error(`[kavachos:measure] not measured — ${m.error}`);
    } else {
      writeFileSync(join(KAVACHOS_DIR, `${sessionId}.launch.json`), JSON.stringify(m, null, 2));

      // A host that claimed a rung its evidence does not support is announced on EVERY
      // launch, never only a verbose one. @rule:PRA-008 — refusing an overclaim buys
      // nothing if the refusal is filed somewhere nobody reads, and the record is read
      // by almost no one. It does NOT stop the launch: host_trust qualifies what a
      // measurement is worth, it does not decide whether an agent may run.
      if (m.host_trust?.claim_refused) {
        console.error(`[kavachos:measure] HOST TRUST REFUSED — ${m.host_trust.claim_refused}`);
        console.error(`[kavachos:measure] treat this launch as host_trust=${m.host_trust.level}, whatever the host claims`);
      }

      if (opts.verbose) {
        console.error(`[kavachos:measure] launch ${m.measurement.slice(0, 32)}…`);
        if (m.host_trust) {
          console.error(`[kavachos:measure] host_trust=${m.host_trust.level} — ${m.host_trust.why}`);
        }
        console.error(`[kavachos:measure] compare: aegis attest verify --trust-mask=${opts.trustMask} --domain=${opts.domain}` +
                      `${opts.strictExec ? " --strict-exec" : ""} --launch ${sessionId}`);
      }
    }
  } catch (e: any) {
    // Measuring must never stop a launch. An unmeasured run is a worse outcome than
    // an unmeasured run that also failed to start.
    console.error(`[kavachos:measure] skipped: ${e?.message}`);
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

  // 4D. Prepare the egress cgroup BEFORE launching (Phase 1E — KOS-040, ANU-008)
  // The sidecar used to be started after the agent and handed its pid, which never
  // constrained anything: a short agent was already gone, and on the notify path the
  // real agent is a fork child created before the move. Now the cgroup exists first and
  // the launcher joins it before exec, so the agent inherits membership.
  let egressCgroup: string | null = null;
  let egressSidecar: ReturnType<typeof spawn> | null = null;
  if (egressPolicyPath) {
    const CGROUP_EGRESS_PY = join(dirname(new URL(import.meta.url).pathname), "cgroup-egress.py");
    const readyFile = join(KAVACHOS_DIR, `${sessionId}.cgroup`);

    // @rule:KOS-047 — the ready file is the THIRD thing keyed by session id alone, after
    // the cgroup and the BPF pins. Measured 2026-09-23: a second session on a live id read
    // the INCUMBENT's cgroup path out of this file and launched believing itself governed,
    // while its supervisor was simultaneously failing and deleting the incumbent's pins.
    // Its presence before we spawn means someone else holds this id.
    if (existsSync(readyFile)) {
      console.error(`[kavachos:egress] REFUSING TO LAUNCH — session id ${sessionId} is already in use`);
      console.error(`[kavachos:egress] another session holds ${readyFile}; pick a different --session-id`);
      return { sessionId, profileHash, syscallCount: syscall_count, profilePath, falcoRulesPath,
               egressPolicyPath, egressEnforced: false, refused: "egress:SESSION_ID_IN_USE" };
    }
    try { unlinkSync(readyFile); } catch { /* not there — expected */ }

    egressSidecar = spawn("python3", [CGROUP_EGRESS_PY, sessionId, egressPolicyPath, "--prepare", readyFile], {
      stdio: ["ignore", "ignore", "pipe"],
    });
    egressSidecar.stderr?.on("data", (d: Buffer) => {
      const line = d.toString().trim();
      if (line) process.stderr.write(line + "\n");
    });
    egressSidecar.on("error", (err) => {
      process.stderr.write(`[kavachos:egress] sidecar error: ${err.message}\n`);
    });

    // Bounded wait for the cgroup. @rule:INF-KOS-009 — the three ways this can go wrong
    // are NOT equivalent, and treating them as one was the defect. The supervisor already
    // writes a distinct word for each; this used to read none of them, asking only
    // `startsWith("/")`, so a hard failure, an unsupported host and a timeout all fell
    // through to the same silent unconstrained launch — behind `--verbose` at that.
    //
    //   FAILED       BPF was available and this session could not arm. A fault. ABORT.
    //   <timeout>    we do not know what happened. Unknown refuses. ABORT.
    //   UNAVAILABLE  the host genuinely cannot enforce. The only defensible exception,
    //                and only when the caller declared it up front.
    const deadline = Date.now() + 15_000;
    let verdict = "TIMEOUT";
    while (Date.now() < deadline) {
      if (existsSync(readyFile)) {
        verdict = readFileSync(readyFile, "utf-8").trim();
        if (verdict.startsWith("/")) egressCgroup = verdict;
        break;
      }
      // portable synchronous pause — no shell, no busy spin
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50);
    }

    if (!egressCgroup) {
      const allowed = opts.allowUnconstrainedEgress === true;

      // Never behind --verbose. An agent running without its egress gate is not a
      // debugging detail, and the one person who needs to know is the one who did not
      // pass --verbose.
      console.error(`[kavachos:egress] NOT egress-constrained — supervisor said ${verdict}`);

      const decision = egressLaunchDecision(verdict, allowed);
      if (!decision.proceed) {
        console.error(`[kavachos:egress] REFUSING TO LAUNCH — ${decision.reason}`);
        try { egressSidecar?.kill(); } catch { /* already gone */ }
        return { sessionId, profileHash, syscallCount: syscall_count, profilePath, falcoRulesPath,
                 egressPolicyPath, egressEnforced: false, refused: `egress:${verdict}` };
      }

      console.error(`[kavachos:egress] proceeding unconstrained — ${decision.reason}`);
    }
  }

  // Complete the launch record now that enforcement is known. The measurement is taken
  // at 4E, before the cgroup exists, because dry-run returns before this point and must
  // still measure — so the enforcement fact is written back rather than moving the whole
  // block. Without it the record attests the POLICY and never whether it took effect.
  try {
    const recPath = join(KAVACHOS_DIR, `${sessionId}.launch.json`);
    if (existsSync(recPath)) {
      const rec = JSON.parse(readFileSync(recPath, "utf-8"));
      rec.egress_enforced = egressPolicyPath ? egressCgroup !== null : false;
      writeFileSync(recPath, JSON.stringify(rec, null, 2));
      if (!rec.egress_enforced) {
        console.error(`[kavachos:measure] egress_enforced=false recorded — this launch is not egress-governed`);
      }
    }
  } catch (e: any) {
    console.error(`[kavachos:measure] could not record egress_enforced: ${e?.message}`);
  }

  // 5. Launch agent via Python seccomp applicator (KOS-011, KOS-006)
  // @rule:KOS-051 zero agent code change: redirect all LLM API calls through kavachos-proxy
  // If KAVACHOS_PROXY_URL is set (proxy is running), inject base URL overrides so the agent
  // uses the proxy without any code changes. Falls back to direct API if proxy not set.
  const egressEnv: NodeJS.ProcessEnv = egressCgroup ? { KAVACHOS_EGRESS_CGROUP: egressCgroup } : {};
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
    ...egressEnv,
    ...proxyEnvOverrides,
  };

  // @rule:KGT-002 — path jail wraps the seccomp applicator; children inherit (ix)
  const jailMode = apparmorJailMode();
  const jailActive = jailMode !== "off" && apparmorProfileLoaded();
  if (jailMode === "require" && !jailActive) {
    throw new Error(
      `KAVACHOS_JAIL=require but AppArmor profile '${APPARMOR_PROFILE}' is not loaded — ` +
      `refusing to launch (fail-closed). Load it: bash src/kernel/apparmor/install.sh`,
    );
  }
  if (jailMode === "prefer" && !jailActive) {
    process.stderr.write(
      `[kavachos] WARNING: AppArmor path jail '${APPARMOR_PROFILE}' not loaded — ` +
      `agent can read signing keys. Load it: bash src/kernel/apparmor/install.sh\n`,
    );
    try {
      addAlert({
        type: "kernel_jail_unavailable",
        severity: "critical",
        message: `Agent ${opts.agentId ?? sessionId} launched WITHOUT the ${APPARMOR_PROFILE} path jail — signing keys readable (KGT-002)`,
        session_id: sessionId,
        timestamp: new Date().toISOString(),
        acknowledged: false,
      });
    } catch { /* dashboard db unavailable — CLI mode */ }
  }

  const launchArgs = [
    ...(jailActive ? ["aa-exec", "-p", APPARMOR_PROFILE, "--"] : []),
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
