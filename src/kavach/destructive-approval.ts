// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// One-time approvals for the destructive gate.
//
// @rule:KAV-098 — an override of the destructive gate is an approval a person gives, for one
//                 exact command, once, for a few minutes. Nothing typed into the command
//                 itself overrides the gate.
//
// How it goes: the gate refuses a command and remembers it here as PENDING, under a short
// code. A person reads what was refused and runs `aegis approve-destructive <code>`. That
// writes an APPROVAL for the SHA-256 of that exact command, good for ten minutes. The agent
// runs the same command again; the gate finds the approval, uses it up, and lets that one
// run through. A different command, or the same one a second time, is refused again.
//
// WHERE THE TRUST SITS (state it, never round up): both files live in the shield's own
// directory, under the same user the agent runs as. The shield stops a tool call from
// writing there and from running `approve-destructive`, but the shield reads the text of a
// call; code that an agent runs through an interpreter of its own could write the approval
// file. So this is a recorded, deliberate act that an agent has to go out of its way to
// forge — not a boundary the operating system enforces. For that, switch on the approval
// gate (`kavach.destructive_critical: "approve"`), which asks a person over a channel
// outside this machine.

import { createHash, randomBytes } from "crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "fs";
import { join } from "path";
import { redactSecrets } from "../shield/credential-marker";

export const PENDING_TTL_MS = 30 * 60 * 1000;
export const APPROVAL_TTL_MS = 10 * 60 * 1000;
const KEEP = 20;

export interface PendingRefusal { code: string; hash: string; shown: string; rule: string; at: number }
export interface Approval { code: string; hash: string; approved_at: number; expires_at: number }

const dir = (): string => join(process.env.HOME || "/root", ".aegis");
const pendingPath = (): string => join(dir(), "destructive-pending.json");
const approvalPath = (): string => join(dir(), "destructive-approvals.json");

export const hashCommand = (command: string): string => createHash("sha256").update(command, "utf8").digest("hex");

function readList<T>(path: string): T[] {
  try {
    if (!existsSync(path)) return [];
    const v = JSON.parse(readFileSync(path, "utf-8"));
    return Array.isArray(v) ? (v as T[]).filter((x) => x && typeof x === "object") : [];
  } catch {
    return []; // unreadable = nothing pending, nothing approved
  }
}

function writeList(path: string, list: unknown[]): void {
  mkdirSync(dir(), { recursive: true });
  const tmp = `${path}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`;
  writeFileSync(tmp, JSON.stringify(list), { mode: 0o600 });
  renameSync(tmp, path);
}

/**
 * Remember a refused command so a person can approve it. Returns the code to show. The
 * command is stored as its hash plus a short form with secrets removed — never whole.
 */
export function recordPending(command: string, rule: string, now = Date.now()): string {
  const hash = hashCommand(command);
  const code = hash.slice(0, 8);
  try {
    const list = readList<PendingRefusal>(pendingPath()).filter((p) => now - p.at < PENDING_TTL_MS && p.hash !== hash);
    list.push({ code, hash, shown: redactSecrets(command).replace(/\s+/g, " ").slice(0, 300), rule: String(rule).slice(0, 120), at: now });
    writeList(pendingPath(), list.slice(-KEEP));
  } catch { /* the refusal stands whether or not it could be remembered */ }
  return code;
}

export function listPending(now = Date.now()): PendingRefusal[] {
  return readList<PendingRefusal>(pendingPath()).filter((p) => typeof p.at === "number" && now - p.at < PENDING_TTL_MS);
}

/** A person approves one pending refusal by its code. Null when there is no such code. */
export function approvePending(code: string, now = Date.now()): (Approval & { shown: string; rule: string }) | null {
  if (typeof code !== "string" || !/^[0-9a-f]{8}$/.test(code)) return null;
  const pending = listPending(now);
  const hit = pending.find((p) => p.code === code);
  if (!hit) return null;
  const approval: Approval = { code, hash: hit.hash, approved_at: now, expires_at: now + APPROVAL_TTL_MS };
  const approvals = readList<Approval>(approvalPath()).filter((a) => a.expires_at > now && a.hash !== hit.hash);
  approvals.push(approval);
  writeList(approvalPath(), approvals.slice(-KEEP));
  writeList(pendingPath(), pending.filter((p) => p.code !== code));
  return { ...approval, shown: hit.shown, rule: hit.rule };
}

/**
 * Is there an unexpired approval for exactly this command? If so it is used up here: the
 * same approval never lets a second run through.
 */
export function consumeApproval(command: string, now = Date.now()): boolean {
  const hash = hashCommand(command);
  const approvals = readList<Approval>(approvalPath());
  const hit = approvals.find((a) => a.hash === hash && typeof a.expires_at === "number" && a.expires_at > now);
  if (!hit) return false;
  try {
    writeList(approvalPath(), approvals.filter((a) => a !== hit && a.expires_at > now));
  } catch {
    return false; // an approval that cannot be used up is not used
  }
  return true;
}
