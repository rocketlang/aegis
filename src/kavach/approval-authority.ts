// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.

// The approval authority facade (KAV-098). One seam the destructive gate and the human
// `approve-destructive` command both go through, so neither has to know WHO the authority is.
//
// Separation is the default, not a switch (founder ruling, 2026-10-07). Three modes:
//
//   hardened        — a separate-uid approver daemon is configured (a consume socket is set).
//                     The agent's uid cannot write the store, so it cannot forge an approval.
//                     This is the normal posture after `aegis init`.
//   none (DEFAULT)  — no approver is configured and insecure local mode was not asked for.
//                     NO same-account override is honoured at all: consume returns false and
//                     approve returns null. Self-approval is dead by default; the worst case is
//                     "you cannot override until the clerk is set up" — the safe failure.
//   insecure-local  — someone set AEGIS_ALLOW_INSECURE_LOCAL_APPROVAL explicitly, accepting the
//                     old single-uid file override (forgeable by anything at that uid). Opt-OUT,
//                     for a single-box dev machine where that risk is understood.
//
// FAIL LOUD (FP-010): in hardened mode, if the approver is unreachable these throw. The gate's
// outer handler (ANU-004) turns a throw into a refusal; it never falls back to the writable file.

import {
  recordPending, listPending, approvePending, consumeApproval,
  type Approval, type PendingRefusal,
} from "./destructive-approval";
import {
  isHardened, remoteConsume, remoteRecordPending, remoteListPending, remoteApprove,
} from "./approver-client";

export { isHardened };

export const INSECURE_LOCAL_ENV = "AEGIS_ALLOW_INSECURE_LOCAL_APPROVAL";
export type AuthorityMode = "hardened" | "insecure-local" | "none";

const truthy = (v?: string): boolean => v === "1" || v === "true" || v === "yes";

export function authorityMode(): AuthorityMode {
  if (isHardened()) return "hardened";
  if (truthy(process.env[INSECURE_LOCAL_ENV])) return "insecure-local";
  return "none";
}

/** One line telling a person how to get an approval authority, for the "none" case. */
export function authorityHint(): string {
  return (
    "[KAVACH] No approval authority is configured, so overrides are disabled (safe default — an agent " +
    "cannot approve its own command).\n" +
    "[KAVACH] To enable overrides: run `aegis init` to set up the separate-uid approver (recommended), or " +
    `set ${INSECURE_LOCAL_ENV}=1 for insecure single-box mode.\n`
  );
}

// Pending is only a NOTE of what was refused (never an approval), so recording/listing it over
// the local file in non-hardened modes is harmless — an agent cannot turn a note into consent.
export async function recordPendingAuthority(command: string, rule: string): Promise<string> {
  return isHardened() ? remoteRecordPending(command, rule) : recordPending(command, rule);
}

export async function listPendingAuthority(): Promise<PendingRefusal[]> {
  return isHardened() ? remoteListPending() : listPending();
}

export async function consumeApprovalAuthority(command: string): Promise<boolean> {
  switch (authorityMode()) {
    case "hardened": return remoteConsume(command);
    case "insecure-local": return consumeApproval(command);
    case "none": return false; // safe default: no same-account override is honoured
  }
}

export async function approvePendingAuthority(
  code: string,
): Promise<(Approval & { shown: string; rule: string }) | null> {
  switch (authorityMode()) {
    case "hardened": return remoteApprove(code);
    case "insecure-local": return approvePending(code);
    case "none": return null; // no authority to approve with
  }
}
