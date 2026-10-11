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
// code (the start of the command's hash; lengthened when another waiting command starts the same). A person reads what was refused and runs `aegis approve-destructive <code>`. That
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
import { visible } from "../core/ledger-sign";

export const PENDING_TTL_MS = 30 * 60 * 1000;
export const APPROVAL_TTL_MS = 10 * 60 * 1000;
const KEEP = 20;
// How much of a refused command a person is shown. Through 2.17.0 it was 300 characters, and the
// approval covered the whole command: what came after the 300th character was approved unseen.
export const SHOWN_MAX = 2000;
const CODE_MIN = 8;

/** An approval that is refused for a reason the person must read. Not "no such code". */
export class ApprovalRefused extends Error {}

// `chars` is the length of the whole command; `cut` says the person is NOT shown all of it (the text
// was longer than SHOWN_MAX, or a secret was taken out of it). Rows written before 2.17.1 have neither.
// `cwd` is the folder the command was refused in; when there is one the approval is for the command IN that
// folder (2.17.2). `shown`, `rule` and `cwd` are safe to print: characters a terminal would act on are
// written out (\x1b), since 2.17.2.
export interface PendingRefusal { code: string; hash: string; shown: string; rule: string; at: number; chars?: number; cut?: boolean; cwd?: string }
export interface Approval { code: string; hash: string; approved_at: number; expires_at: number }

// AEGIS_DIR lets a separate-uid approver daemon own its store under a directory the agent's
// uid cannot write (KAV-098 hardened mode). Absent, the single-uid default is unchanged.
const dir = (): string => process.env.AEGIS_DIR || join(process.env.HOME || "/root", ".aegis");
const pendingPath = (): string => join(dir(), "destructive-pending.json");
const approvalPath = (): string => join(dir(), "destructive-approvals.json");

// With a folder, the hash is of the command and the folder: `rm -rf ./build` approved in one folder is
// not approved in another. Through 2.17.1 the folder was no part of it, and the person was not shown it.
// Without a folder (an older gate, or a caller that has none) it is the command alone, as before.
export const hashCommand = (command: string, cwd?: string | null): string => {
  if (typeof cwd !== "string" || !cwd) return createHash("sha256").update(command, "utf8").digest("hex");
  // Another function than the one above, over an encoding that keeps the two parts apart: no command text
  // hashed alone can come out as some command in some folder.
  return createHash("sha512").update(JSON.stringify([command, cwd]), "utf8").digest("hex").slice(0, 64);
};

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
export function recordPending(command: string, rule: string, now = Date.now(), cwd?: string | null): string {
  const hash = hashCommand(command, cwd);
  let code = hash.slice(0, CODE_MIN);
  try {
    const list = readList<PendingRefusal>(pendingPath()).filter((p) => now - p.at < PENDING_TTL_MS && p.hash !== hash);
    // The code is the start of the hash. Eight characters are 32 bits: a second command made to begin
    // with the same eight is a matter of minutes, and through 2.17.0 the OLDER of the two was the one
    // approved. A code already held by another command is lengthened until it is this command's alone.
    // (A code is matched whole, so a longer one is not confused with the shorter one it begins with.)
    for (let n = CODE_MIN + 4; n <= hash.length && list.some((p) => p.code === code); n += 4) code = hash.slice(0, n);
    const redacted = redactSecrets(command);
    // A command can carry characters that make a terminal move the cursor, erase a line, hide text or run
    // it right to left. Through 2.17.1 they were printed to the approving person's terminal as they came,
    // so what the person read need not be what the command was. They are written out instead (\x1b).
    const flat = redacted.replace(/\s+/g, " ");
    const safe = visible(flat);
    list.push({
      code, hash, shown: safe.slice(0, SHOWN_MAX), rule: visible(String(rule).replace(/\s+/g, " ")).slice(0, 120), at: now,
      chars: command.length, cut: safe.length > SHOWN_MAX || redacted !== command,
      ...(typeof cwd === "string" && cwd ? { cwd: visible(cwd).slice(0, 400) } : {}),
    });
    writeList(pendingPath(), list.slice(-KEEP));
  } catch { /* the refusal stands whether or not it could be remembered */ }
  return code;
}

export function listPending(now = Date.now()): PendingRefusal[] {
  return readList<PendingRefusal>(pendingPath()).filter((p) => typeof p.at === "number" && now - p.at < PENDING_TTL_MS);
}

/**
 * A person approves one pending refusal by its code. Null when there is no such code.
 * Throws ApprovalRefused when the code is held by more than one command, or when the person was not
 * shown the whole command and has not said (`unseen`) that they read it somewhere else.
 */
export function approvePending(code: string, now = Date.now(), opts: { unseen?: boolean } = {}): (Approval & { shown: string; rule: string; cwd?: string }) | null {
  if (typeof code !== "string" || !/^[0-9a-f]{8,64}$/.test(code)) return null;
  const pending = listPending(now);
  const hits = pending.filter((p) => p.code === code);
  if (hits.length === 0) return null;
  if (new Set(hits.map((p) => p.hash)).size > 1) {
    throw new ApprovalRefused(`${hits.length} different refused commands are waiting under the code '${code}'. None was approved. Have the command refused again and use the new code.`);
  }
  const hit = hits[0];
  if (hit.cut && !opts.unseen) {
    throw new ApprovalRefused(
      `the command is ${hit.chars ?? "an unknown number of"} characters and what is shown is not all of it` +
      ` (only the first ${SHOWN_MAX} characters are shown, and secrets are taken out). The approval would cover the whole command.` +
      ` Read the whole command where it was refused; then approve with --unseen-tail.`,
    );
  }
  const approval: Approval = { code, hash: hit.hash, approved_at: now, expires_at: now + APPROVAL_TTL_MS };
  const approvals = readList<Approval>(approvalPath()).filter((a) => a.expires_at > now && a.hash !== hit.hash);
  approvals.push(approval);
  writeList(approvalPath(), approvals.slice(-KEEP));
  writeList(pendingPath(), pending.filter((p) => p.code !== code));
  return { ...approval, shown: hit.shown, rule: hit.rule, ...(hit.cwd ? { cwd: hit.cwd } : {}) };
}

/**
 * Is there an unexpired approval for exactly this command? If so it is used up here: the
 * same approval never lets a second run through.
 */
export function consumeApproval(command: string, now = Date.now(), cwd?: string | null): boolean {
  const hash = hashCommand(command, cwd);
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
