// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// KAVACH — filesystem capability-over-target (AF-T-705, ANU-I-008, AFW-YK-002).
//
// The ANU-I-006 shape applied to writes: (write-capable invocation) ∧ ¬(target under a
// known-safe root) ⇒ judge on the resolved path's class. ANU-I-005 already refuses writes
// to the layer's own named instruments; this classifies EVERY write target the way
// databases are classed, so a write into the system's trust base (boot, binaries, unit
// files, cron, SSH material) is judged by WHERE it lands, not by which command spelled it.
//
// Completes the AF-T-108 trio (DB → ANU-I-006, egress → ANU-I-007, filesystem → this).
// CEILING: reads the command text / tool target. A write made by an interpreter the text
// does not reveal belongs to the kernel path jail (AppArmor), not here.

export type PathClass = "system" | "dev" | "unclassed";

// The system trust base: a write here changes what the BOX is, not what a project is.
// Positive, documented list (the label is authored, never inferred by the gate).
const SYSTEM_ROOTS = [
  "/etc", "/boot", "/usr", "/bin", "/sbin", "/lib", "/lib64",
  "/var/spool/cron", "/root/.ssh",
];

// Ordinary working ground on this box: project tree, temp, scratch.
const DEV_ROOTS = ["/root", "/tmp", "/var/tmp", "/home", "/dev/null", "/dev/stdout", "/dev/stderr"];

const under = (p: string, root: string) => p === root || p.startsWith(root.endsWith("/") ? root : root + "/");

export function classifyPath(path: string): PathClass {
  // system beats dev — /root/.ssh is system although /root is dev ground.
  if (SYSTEM_ROOTS.some((r) => under(path, r))) return "system";
  if (DEV_ROOTS.some((r) => under(path, r))) return "dev";
  return "unclassed";
}

export interface FsVerdict {
  verdict: "PERMIT" | "REFUSE" | "UNKNOWN";
  detail: string;
  source: string;
  stage?: "enforce" | "observe";
}

/**
 * The ANU-I-008 decision over a set of resolved write targets. Ships FULLY OBSERVE
 * (AFW-006): system-root writes DO happen legitimately under founder direction (nginx
 * sites, unit files), so even the "sure" branch collects shadow evidence before any
 * graded promotion — the AF-R-005 procedure, again. @rule:AFW-YK-002 @rule:AFW-006
 */
export function fsTargetVerdict(targets: string[]): FsVerdict {
  const src = "resolved write targets + path-class roots";
  const system = targets.filter((t) => classifyPath(t) === "system");
  const unclassed = targets.filter((t) => classifyPath(t) === "unclassed");

  if (system.length > 0) {
    return {
      verdict: "REFUSE",
      detail: `write-capable action targets the system trust base: ${system.join(", ")} — a write there changes the box, not a project`,
      source: src,
      stage: "observe",
    };
  }
  if (unclassed.length > 0) {
    return {
      verdict: "UNKNOWN",
      detail: `write target(s) in no declared path class: ${unclassed.join(", ")}`,
      source: src,
      stage: "observe",
    };
  }
  return { verdict: "PERMIT", detail: `${targets.length} target(s) on dev ground`, source: src, stage: "observe" };
}
