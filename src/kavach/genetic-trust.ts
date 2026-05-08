// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// Genetic Trust — GNT-001 + GNT-002
//
// @rule:GNT-001 child.trust_mask = parent.trust_mask & requested_mask — never union
// @rule:GNT-002 at session start, verify child.trust_mask is a valid subset of parent.trust_mask
//
// The DNA replication rule: a child agent inherits from its parent via bitmask AND.
// The child can only go narrower — never broader. Self-elevation is constitutionally impossible.

export interface GntInheritanceResult {
  child_mask: number;
  parent_mask: number;
  requested_mask: number;
  bits_dropped: number; // parent_mask bits that weren't in requested_mask (clamped away)
}

export interface GntLineageResult {
  valid: boolean;
  child_mask: number;
  parent_mask: number;
  reason?: "MASK_OVERFLOW" | "NO_PARENT_ENVELOPE";
  bits_overflowed?: number; // bits child has that parent doesn't — the attack surface
}

// @rule:GNT-001 — compute the child's effective trust_mask
// requested_mask: what the child is asking for. Defaults to 0xFFFFFFFF (full ask) when unknown.
// The parent mask is always the ceiling. The child can ask for less; it can never get more.
export function computeChildMask(
  parentMask: number,
  requestedMask: number = 0xFFFFFFFF,
): GntInheritanceResult {
  const child_mask = (parentMask & requestedMask) >>> 0; // unsigned 32-bit
  // bits_dropped: bits the child requested but couldn't get (parent didn't have them)
  const bits_dropped = (requestedMask & ~parentMask) >>> 0;
  return { child_mask, parent_mask: parentMask, requested_mask: requestedMask, bits_dropped };
}

// @rule:GNT-002 — verify child trust_mask is a valid subset of parent at session start
// Returns valid=true only when every bit set in child_mask is also set in parent_mask.
export function verifyLineage(
  childMask: number,
  parentMask: number | null,
): GntLineageResult {
  if (parentMask === null) {
    return {
      valid: false,
      child_mask: childMask,
      parent_mask: 0,
      reason: "NO_PARENT_ENVELOPE",
    };
  }
  const overflow = (childMask & ~parentMask) >>> 0;
  if (overflow !== 0) {
    return {
      valid: false,
      child_mask: childMask,
      parent_mask: parentMask,
      reason: "MASK_OVERFLOW",
      bits_overflowed: overflow,
    };
  }
  return { valid: true, child_mask: childMask, parent_mask: parentMask };
}

// Format a GNT-001 log line for check-spawn
export function formatGnt001Log(result: GntInheritanceResult): string {
  const hex = (n: number) => `0x${n.toString(16).padStart(8, "0")}`;
  const dropped = result.bits_dropped !== 0
    ? ` bits_dropped=${hex(result.bits_dropped)}`
    : "";
  return (
    `[KAVACH:GNT-001] child_mask=${hex(result.child_mask)}` +
    ` parent=${hex(result.parent_mask)} requested=${hex(result.requested_mask)}${dropped}`
  );
}

// Format a GNT-002 log line for session-start
export function formatGnt002Log(result: GntLineageResult): string {
  const hex = (n: number) => `0x${n.toString(16).padStart(8, "0")}`;
  if (result.valid) {
    return (
      `[KAVACH:GNT-002] lineage OK — child=${hex(result.child_mask)}` +
      ` ⊆ parent=${hex(result.parent_mask)}`
    );
  }
  if (result.reason === "NO_PARENT_ENVELOPE") {
    return `[KAVACH:GNT-002] WARN — parent session not found in envelope store`;
  }
  return (
    `[KAVACH:GNT-002] MASK_OVERFLOW — child=${hex(result.child_mask)}` +
    ` parent=${hex(result.parent_mask)}` +
    ` overflowed_bits=${hex(result.bits_overflowed ?? 0)}`
  );
}
