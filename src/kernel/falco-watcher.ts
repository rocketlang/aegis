// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// @rule:KOS-022 pipe Falco stdout → KAVACH event bus (kavach.kernel.violation.detected)
// @rule:KOS-023 Falco violation → gate valve auto-escalation (recordViolation)

import { spawn } from "child_process";
import { execSync } from "child_process";
import { parseFalcoEvent, sealKernelViolation, checkViolationRate } from "./kernel-receipt";
import { getReceiptChain } from "./profile-store";
import { broadcast } from "../core/events";
import { recordViolation } from "../kavach/gate-valve";

export interface FalcoWatchOptions {
  rulesPath: string;
  sessionId: string;
  agentId?: string;
  profileHash?: string;
  verbose?: boolean;
}

export interface FalcoWatcher {
  stop: () => void;
  pid: number | undefined;
}

// @rule:INF-KOS-005 isFalcoAvailable — binary check, never assume installed
export function isFalcoAvailable(): boolean {
  try {
    execSync("which falco", { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

/**
 * Start Falco sidecar, pipe violations to KAVACH event bus + gate valve.
 * Uses --modern-bpf (CO-RE eBPF, no kernel module, kernel ≥ 5.8).
 * This VM: 6.8.0-100-generic ✅
 *
 * @rule:KOS-022 each Falco line → parseFalcoEvent → sealKernelViolation → broadcast
 * @rule:KOS-023 each violation → recordViolation(agentId) → auto-escalates valve
 */
export function startFalcoWatch(opts: FalcoWatchOptions): FalcoWatcher {
  if (!isFalcoAvailable()) {
    if (opts.verbose) {
      process.stderr.write(
        "[kavachos:falco] Falco not installed — anomaly detection disabled.\n" +
        "  Install: https://falco.org/docs/getting-started/installation/\n" +
        "  Or: apt-get install falco (after adding falcosecurity apt repo)\n"
      );
    }
    return { stop: () => {}, pid: undefined };
  }

  // Launch Falco: modern-bpf driver, JSON output, our rules file
  const falco = spawn("falco", [
    "--modern-bpf",
    "--json-output",
    "--json-include-output-property",
    "-r", opts.rulesPath,
  ], {
    stdio: ["ignore", "pipe", "ignore"],
  });

  let buffer = "";

  falco.stdout?.setEncoding("utf8");
  falco.stdout?.on("data", (data: string) => {
    buffer += data;
    const lines = buffer.split("\n");
    buffer = lines.pop() ?? "";          // keep incomplete last line

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed.startsWith("{")) continue;

      const violation = parseFalcoEvent(trimmed);
      if (!violation) continue;

      // Stamp with our session context (Falco reads env from process table)
      violation.session_id = opts.sessionId;
      if (opts.agentId) violation.agent_id = opts.agentId;
      if (opts.profileHash) violation.profile_hash = opts.profileHash;

      // @rule:KOS-024 PRAMANA seal — every Falco violation is a receipt
      const receipt = sealKernelViolation(violation);

      // @rule:KOS-022 broadcast to event bus
      broadcast("kavach.kernel.violation.detected", {
        session_id: opts.sessionId,
        agent_id: opts.agentId ?? null,
        falco_rule: violation.falco_rule,
        severity: violation.severity,
        violation_details: violation.violation_details,
        receipt_id: receipt.receipt_id,
        receipt_hash: receipt.receipt_hash,
        sealed_at: receipt.sealed_at,
      });

      // @rule:KOS-023 auto-escalate gate valve: first → THROTTLE, 3+ → CRACK, CRITICAL → LOCK
      if (opts.agentId) {
        const reason = `Falco: ${violation.falco_rule ?? "unknown rule"}`;
        if (violation.severity === "CRITICAL") {
          // Critical Falco alert (e.g. unexpected shell exec) → hard lock
          const { lockValve } = require("../kavach/gate-valve");
          lockValve(opts.agentId, reason, "kavachos-falco");
          broadcast("kavach.kernel.agent_locked", {
            agent_id: opts.agentId,
            reason,
            session_id: opts.sessionId,
          });
          if (opts.verbose) {
            process.stderr.write(`[kavachos:falco] CRITICAL → agent ${opts.agentId} LOCKED\n`);
          }
        } else {
          recordViolation(opts.agentId, reason);
        }
      }

      // @rule:INF-KOS-002 rate exceeded → emit critical event
      const chain = getReceiptChain(opts.sessionId);
      if (checkViolationRate(chain)) {
        sealKernelViolation({
          session_id: opts.sessionId,
          agent_id: opts.agentId ?? null,
          event_type: "RATE_EXCEEDED",
          violation_details: "Falco violation rate exceeded 5/min — possible low-and-slow exfil",
          profile_hash: opts.profileHash,
          severity: "CRITICAL",
        });
        broadcast("kavach.kernel.rate_exceeded", {
          session_id: opts.sessionId,
          agent_id: opts.agentId ?? null,
        });
        if (opts.verbose) {
          process.stderr.write(`[kavachos:falco] RATE_EXCEEDED for session ${opts.sessionId}\n`);
        }
      }

      if (opts.verbose) {
        process.stderr.write(
          `[kavachos:falco] ${violation.severity} — rule="${violation.falco_rule}" receipt=${receipt.receipt_id}\n`
        );
      }
    }
  });

  falco.on("error", (err) => {
    if (opts.verbose) {
      process.stderr.write(`[kavachos:falco] process error: ${err.message}\n`);
    }
  });

  falco.on("exit", (code, signal) => {
    if (opts.verbose) {
      process.stderr.write(`[kavachos:falco] exited (code=${code ?? "null"} signal=${signal ?? "none"})\n`);
    }
  });

  return {
    stop: () => {
      try { falco.kill("SIGTERM"); } catch { /* already gone */ }
    },
    pid: falco.pid,
  };
}
