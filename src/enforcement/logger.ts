// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// AEGIS Decision Logger — append-only AEGIS_DECISION_LOG
//
// @rule:AEG-E-005 — every gate decision logged; log failure never blocks decision
// @rule:BMOS-004  — authorization is witnessed; log is the witness record

import { appendFileSync, mkdirSync, existsSync } from "fs";
import { join, dirname } from "path";
import type { AegisEnforcementDecision } from "./types";

// @rule:AEG-E-005 path evaluated lazily — env override must work at call time, not module load
function resolveLogPath(): string {
  return process.env.AEGIS_DECISION_LOG_PATH ??
    join(process.env.HOME ?? "/root", ".aegis", "aegis_decision.log");
}

function ensureLogDir(path: string): void {
  const dir = dirname(path);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
}

// @rule:AEG-E-005 log never throws — failure is silent, enforcement is unaffected
export function logDecision(decision: AegisEnforcementDecision): void {
  try {
    const path = resolveLogPath();
    ensureLogDir(path);
    // schema_version is stable so Pulse can consume without migration guards
    const line = JSON.stringify({ schema_version: "aegis.decision.v1", ...decision }) + "\n";
    appendFileSync(path, line, "utf-8");
  } catch {
    // intentionally swallowed — logging must never block the gate decision
  }
}

export function logPath(): string {
  return resolveLogPath();
}
