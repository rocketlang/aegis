// BitMask OS Phase 1 — Spawn Gate
// @rule:BMOS-001 Spawn invariant: child_spawn_mask & ~parent_mask == 0
// @rule:BMOS-003 Narrowing formula: child = parent & purpose & ~blocked
// @rule:BMOS-005 Runtime spawn gate enforced here — 403 on violation
// @rule:BMOS-008 Expiry gate: child TTL <= parent TTL

import { appendFileSync, mkdirSync, existsSync } from "fs";
import { join } from "path";
import { randomUUID } from "crypto";

const SESSIONS_DIR = join(process.env.HOME ?? "/root", ".aegis", "sessions");
const SPAWN_AUDIT_FILE = join(SESSIONS_DIR, "spawn-audit.jsonl");

// Bits 24-31 are AGI autonomy bits — only propagate when delegate_autonomy=true
// @rule:BMOS-003 narrowing formula strips autonomy bits unless explicitly delegated
const AUTONOMY_BITS = 0xff000000;

// ── Spawn gate core ───────────────────────────────────────────────────────────

export interface SpawnRequest {
  caller_id: string;
  parent_mask: number;
  purpose_mask: number;
  blocked_mask?: number;
  delegate_autonomy?: boolean;
  ttl_seconds?: number;
  parent_expires_at?: string;
  task_description?: string;
}

export interface SpawnResult {
  audit_ref: string;
  caller_id: string;
  parent_mask: number;
  purpose_mask: number;
  blocked_mask: number;
  child_spawn_mask: number;
  invariant_satisfied: boolean;
  expires_at: string;
  delegate_autonomy: boolean;
}

export interface SpawnViolation {
  child_spawn_mask: number;
  parent_mask: number;
  violation_bits: number;
}

// @rule:BMOS-003 Narrowing formula
export function deriveChildSpawnMask(
  parentMask: number,
  purposeMask: number,
  blockedMask: number,
  delegateAutonomy: boolean,
): number {
  let child = (parentMask & purposeMask & ~blockedMask) >>> 0;
  // @rule:BMOS-003 strip autonomy bits unless explicitly delegated
  if (!delegateAutonomy) {
    child = (child & ~AUTONOMY_BITS) >>> 0;
  }
  return child;
}

// @rule:BMOS-001 Invariant assertion — child cannot exceed parent
// Returns violation_bits (non-zero = violation)
export function checkSpawnInvariant(childMask: number, parentMask: number): number {
  return ((childMask & ~parentMask) >>> 0);
}

// @rule:BMOS-008 Child TTL cannot exceed parent TTL
function deriveExpiry(ttlSeconds: number, parentExpiresAt?: string): string {
  const DEFAULT_TTL = 8 * 60 * 60 * 1000; // 8h in ms
  const MAX_TTL = 24 * 60 * 60 * 1000;    // 24h hard cap

  const ttlMs = Math.min(
    (ttlSeconds > 0 ? ttlSeconds * 1000 : DEFAULT_TTL),
    MAX_TTL,
  );
  const derivedExpiry = new Date(Date.now() + ttlMs);

  if (parentExpiresAt) {
    const parentExpiry = new Date(parentExpiresAt);
    // Child cannot outlive parent
    return (derivedExpiry > parentExpiry ? parentExpiry : derivedExpiry).toISOString();
  }
  return derivedExpiry.toISOString();
}

// @rule:BMOS-005 Write spawn audit record — append-only JSONL
// @rule:BMOS-010 Audit record format per BitMask OS paper §5
function writeSpawnAudit(record: {
  audit_ref: string;
  event: "SPAWN_ISSUED" | "SPAWN_REJECTED";
  caller_id: string;
  parent_mask: number;
  purpose_mask: number;
  blocked_mask: number;
  child_spawn_mask: number;
  invariant_check: string;
  invariant_satisfied: boolean;
  violation_bits?: number;
  expires_at: string;
  delegate_autonomy: boolean;
  task_description?: string;
  spawned_at: string;
}): void {
  try {
    if (!existsSync(SESSIONS_DIR)) mkdirSync(SESSIONS_DIR, { recursive: true });
    appendFileSync(SPAWN_AUDIT_FILE, JSON.stringify(record) + "\n", "utf-8");
  } catch {
    // Never block spawn on audit failure — SOR-004 fail-open principle
  }
}

// ── Public API ────────────────────────────────────────────────────────────────

export function issueSpawn(req: SpawnRequest): SpawnResult {
  const blocked = (req.blocked_mask ?? 0) >>> 0;
  const delegateAutonomy = req.delegate_autonomy ?? false;
  const ttl = req.ttl_seconds ?? 0;

  const childSpawnMask = deriveChildSpawnMask(
    req.parent_mask >>> 0,
    req.purpose_mask >>> 0,
    blocked,
    delegateAutonomy,
  );

  // @rule:BMOS-001 double-check invariant even after derivation
  const violationBits = checkSpawnInvariant(childSpawnMask, req.parent_mask >>> 0);
  const invariantSatisfied = violationBits === 0;

  const expires_at = deriveExpiry(ttl, req.parent_expires_at);
  const audit_ref = randomUUID();
  const spawned_at = new Date().toISOString();

  writeSpawnAudit({
    audit_ref,
    event: invariantSatisfied ? "SPAWN_ISSUED" : "SPAWN_REJECTED",
    caller_id: req.caller_id,
    parent_mask: req.parent_mask,
    purpose_mask: req.purpose_mask,
    blocked_mask: blocked,
    child_spawn_mask: childSpawnMask,
    invariant_check: `child(${childSpawnMask}) & ~parent(${req.parent_mask}) == ${violationBits}`,
    invariant_satisfied: invariantSatisfied,
    ...(violationBits !== 0 ? { violation_bits: violationBits } : {}),
    expires_at,
    delegate_autonomy: delegateAutonomy,
    ...(req.task_description ? { task_description: req.task_description } : {}),
    spawned_at,
  });

  if (!invariantSatisfied) {
    const err = new Error("SPAWN_INVARIANT_VIOLATED") as Error & { spawnViolation: SpawnViolation };
    err.spawnViolation = { child_spawn_mask: childSpawnMask, parent_mask: req.parent_mask, violation_bits: violationBits };
    throw err;
  }

  return {
    audit_ref,
    caller_id: req.caller_id,
    parent_mask: req.parent_mask,
    purpose_mask: req.purpose_mask,
    blocked_mask: blocked,
    child_spawn_mask: childSpawnMask,
    invariant_satisfied: true,
    expires_at,
    delegate_autonomy: delegateAutonomy,
  };
}
