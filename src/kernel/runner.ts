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
import { getAegisDir } from "../core/config";

export interface RunOptions {
  trustMask: number;
  domain: string;
  agentType?: string;
  sessionId?: string;
  agentId?: string;
  dryRun?: boolean;         // generate profile only, do not exec
  verbose?: boolean;
  falcoEnabled?: boolean;   // emit Falco rules file (requires Falco installed)
}

export interface RunResult {
  sessionId: string;
  profileHash: string;
  syscallCount: number;
  profilePath: string;
  falcoRulesPath: string | null;
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

  // 1. Generate seccomp profile (KOS-010 — deterministic)
  const { profile, hash: profileHash, syscall_count } = generateSeccompProfile(
    opts.trustMask,
    opts.domain,
    agentType
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

  if (opts.dryRun) {
    console.log(JSON.stringify({
      sessionId,
      profileHash,
      syscallCount: syscall_count,
      profilePath,
      falcoRulesPath,
      dryRun: true,
    }, null, 2));
    return { sessionId, profileHash, syscallCount: syscall_count, profilePath, falcoRulesPath };
  }

  // 5. Launch agent via Python seccomp applicator (KOS-011, KOS-006)
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    KAVACHOS_SESSION_ID: sessionId,
    KAVACHOS_AGENT_ID: opts.agentId ?? sessionId,
    KAVACHOS_TRUST_MASK: opts.trustMask.toString(),
    KAVACHOS_DOMAIN: opts.domain,
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
            const receipt = sealKernelViolation({ ...event, profile_hash: profileHash });
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
              });
            }
          }
        }
      }
    });

    child.on("exit", (code: number | null) => {
      result.exitCode = code ?? 0;

      // Cleanup temp profile file
      try { unlinkSync(profilePath); } catch { /* already gone */ }

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
        });
      }

      resolve(result);
    });

    child.on("error", (err: Error) => reject(err));
  });
}

// Quick profile-only generation (no exec) — for testing and CI
export function generateOnly(trustMask: number, domain: string, agentType?: string) {
  const result = generateSeccompProfile(trustMask, domain, agentType);
  const falcoRules = generateFalcoRules(domain, trustMask);
  return { ...result, falcoRules };
}
