// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// KAVACH — Pramana: the assurance loop. Independent confirmation of what actually happened.
//
// @rule:PRA-001 A confirmation is evidence only if it arrives by a path that did not command
// @rule:PRA-002 kernel-receipt.ts seals the DECISION — testimony from the control loop about
//               itself. Necessary, and not assurance.
// @rule:PRA-003 unavailable is never upgraded to confirmed
// @rule:PRA-004 a confirmation declares its independence depth and never rounds it up
//
// The sounding pipe. If the agent opens a valve and the agent's own software then says
// "valve open", that is weak evidence. A limit switch on a separate circuit is evidence.
//
// Every confirmer in this file reaches reality by a route the actuator did not use:
//   - not the tool's success flag        → the bytes on disk
//   - not ankr-ctl's exit code           → a fresh socket to the port
//   - not git's stdout                   → a fresh git process reading the log
//
// HONEST CEILING (PRA-004): all three are `same-host`. They survive a lying actuator; they
// do not survive a compromised host, because they share its kernel and its disk. Nothing in
// this file is a sounding pipe in the full sense — a sounding pipe works when the ship's
// power is out. An `off-host` confirmer is the next rung and is not built.

import { existsSync, readFileSync, statSync } from "fs";
import { createHash } from "crypto";
import { execFileSync } from "child_process";
import { connect } from "net";

// ── Types ─────────────────────────────────────────────────────────────────────

export type ConfirmState = "confirmed" | "refuted" | "unavailable";

/**
 * How far down the confirming path is actually independent of the acting path.
 *
 * @rule:PRA-004 A confirmation declares its independence depth, and may never claim more
 * than its WEAKEST shared layer. Avoiding the actuator's own report is the easy half; a
 * confirmer that shares the kernel and the disk with the actuator is still, in Andrey
 * Lazarev's words, "the same system with a second voice". Saying so is the difference
 * between evidence and a better-dressed claim.
 */
export type Independence = "same-process" | "same-host" | "off-host";

const INDEPENDENCE_CEILING: Record<Independence, string> = {
  "same-process": "same process as the actuator — avoids its return value and nothing else",
  "same-host": "separate process, shared kernel and disk — survives a lying actuator, not a compromised host",
  "off-host": "separate machine — shares only the network",
};

export interface Confirmation {
  id: string;
  state: ConfirmState;
  /** The route reality was reached by — never the route that commanded the action. */
  path: string;
  /** @rule:PRA-004 — how deep the independence goes. Never rounded up. */
  independence: Independence;
  detail: string;
  checked_at: string;
}

function result(
  id: string,
  state: ConfirmState,
  path: string,
  independence: Independence,
  detail: string,
): Confirmation {
  return { id, state, path, independence, detail, checked_at: new Date().toISOString() };
}

// ── PRA-C-001 — file write ────────────────────────────────────────────────────

/**
 * Confirm a file write by reading the bytes back off disk and hashing them.
 *
 * Commanded by: the Write/Edit tool result.
 * Confirmed by: a fresh read + SHA-256. The tool's "success" is not consulted.
 *
 * `expected` may be the full content or a hex SHA-256 of it. Omit it to confirm only that
 * the file exists and was written inside `freshnessMs` — a weaker claim, reported as such.
 */
export function confirmFileWrite(
  absPath: string,
  expected?: string,
  freshnessMs = 60_000,
): Confirmation {
  const id = "PRA-C-001";
  const path = `disk:${absPath}`;
  const ind: Independence = "same-host"; // same kernel, same filesystem as the writer

  if (!existsSync(absPath)) {
    return result(id, "refuted", path, ind, `file does not exist on disk after a claimed write`);
  }

  let bytes: Buffer;
  let mtimeMs: number;
  try {
    bytes = readFileSync(absPath);
    mtimeMs = statSync(absPath).mtimeMs;
  } catch (e: any) {
    return result(id, "unavailable", path, ind, `cannot read back: ${e?.message}`);
  }

  const actual = createHash("sha256").update(bytes).digest("hex");

  if (expected !== undefined) {
    const expectedHash = /^[0-9a-f]{64}$/i.test(expected)
      ? expected.toLowerCase()
      : createHash("sha256").update(expected).digest("hex");
    return actual === expectedHash
      ? result(id, "confirmed", path, ind, `sha256 matches on re-read (${bytes.length} bytes)`)
      : result(id, "refuted", path, ind, `sha256 mismatch — disk has ${actual.slice(0, 16)}…, expected ${expectedHash.slice(0, 16)}…`);
  }

  const age = Date.now() - mtimeMs;
  if (age > freshnessMs) {
    return result(id, "refuted", path, ind, `file exists but was last written ${Math.round(age / 1e3)}s ago — older than this action`);
  }
  return result(id, "confirmed", path, ind, `file present, written ${Math.round(age / 1e3)}s ago, sha256 ${actual.slice(0, 16)}… (content not supplied — existence+freshness only)`);
}

// ── PRA-C-002 — service start ─────────────────────────────────────────────────

/**
 * Confirm a service is actually serving by opening a fresh TCP connection to its port.
 *
 * Commanded by: `ankr-ctl start` and its exit code.
 * Confirmed by: a socket this process opens itself. A zero exit code is not consulted —
 * "won't call a zombie alive" is FP-017's second disciplined power, and this is how you
 * would know.
 */
export function confirmServiceListening(
  port: number,
  host = "127.0.0.1",
  timeoutMs = 3000,
): Promise<Confirmation> {
  const id = "PRA-C-002";
  const path = `tcp:${host}:${port}`;
  // A loopback probe shares the kernel with the service it is probing.
  const ind: Independence = host === "127.0.0.1" || host === "localhost" ? "same-host" : "off-host";

  return new Promise<Confirmation>(res => {
    let settled = false;
    const done = (c: Confirmation) => {
      if (settled) return;
      settled = true;
      try {
        sock.destroy();
      } catch {
        /* already gone */
      }
      res(c);
    };

    const sock = connect({ port, host });
    sock.setTimeout(timeoutMs);
    sock.on("connect", () => done(result(id, "confirmed", path, ind, `accepted a fresh TCP connection`)));
    sock.on("timeout", () => done(result(id, "refuted", path, ind, `no answer within ${timeoutMs}ms`)));
    sock.on("error", (e: any) =>
      done(
        e?.code === "ECONNREFUSED"
          ? result(id, "refuted", path, ind, `connection refused — nothing is listening`)
          : result(id, "unavailable", path, ind, `probe failed: ${e?.code ?? e?.message}`),
      ),
    );
  });
}

// ── PRA-C-003 — git commit ────────────────────────────────────────────────────

/**
 * Confirm a commit landed, and with which files, by asking a fresh git process.
 *
 * Commanded by: `git commit` and its stdout.
 * Confirmed by: `git log -1 --name-only` in a separate process. This is the confirmer that
 * would have caught 2026-06-11 — the twin whose commit swept five files it never staged.
 */
export function confirmCommit(
  repoDir: string,
  expectedPaths?: string[],
): Confirmation {
  const id = "PRA-C-003";
  const path = `git:${repoDir} (fresh process)`;
  const ind: Independence = "same-host"; // separate git process, same working tree

  let sha: string;
  let files: string[];
  try {
    sha = execFileSync("git", ["-C", repoDir, "rev-parse", "HEAD"], { encoding: "utf-8", timeout: 5000 }).trim();
    const out = execFileSync("git", ["-C", repoDir, "show", "--pretty=format:", "--name-only", "HEAD"], {
      encoding: "utf-8",
      timeout: 5000,
    });
    files = out.split("\n").map(s => s.trim()).filter(Boolean);
  } catch (e: any) {
    return result(id, "unavailable", path, ind, `cannot read git log: ${e?.message}`);
  }

  if (!expectedPaths || expectedPaths.length === 0) {
    return result(id, "confirmed", path, ind, `HEAD is ${sha.slice(0, 9)} with ${files.length} file(s) — no expected set supplied`);
  }

  const expected = new Set(expectedPaths);
  const unexpected = files.filter(f => !expected.has(f));
  const missing = expectedPaths.filter(p => !files.includes(p));

  if (unexpected.length > 0) {
    return result(
      id,
      "refuted",
      path, ind,
      `commit ${sha.slice(0, 9)} swept ${unexpected.length} file(s) that were never intended: ${unexpected.slice(0, 5).join(", ")}`,
    );
  }
  if (missing.length > 0) {
    return result(id, "refuted", path, ind, `commit ${sha.slice(0, 9)} is missing ${missing.length} intended file(s): ${missing.slice(0, 5).join(", ")}`);
  }
  return result(id, "confirmed", path, ind, `commit ${sha.slice(0, 9)} contains exactly the ${files.length} intended file(s)`);
}

// ── Reporting ─────────────────────────────────────────────────────────────────

/**
 * @rule:PRA-003 — unavailable is reported as unconfirmed, never quietly upgraded.
 * @rule:PRA-004 — the independence ceiling is printed with every confirmation, so a reader
 * never has to assume how far down the second path actually went.
 */
export function renderConfirmation(c: Confirmation): string {
  const mark = c.state === "confirmed" ? "✓" : c.state === "refuted" ? "✗" : "?";
  const head =
    c.state === "confirmed"
      ? "[PRAMANA] confirmed by an independent path"
      : c.state === "refuted"
        ? "[PRAMANA] REFUTED — reality does not match the claim"
        : "[PRAMANA] UNCONFIRMED — no independent path was available";
  return (
    `${head}\n  ${mark} ${c.id}  read: ${c.path}\n    ${c.detail}\n` +
    `    independence: ${c.independence} — ${INDEPENDENCE_CEILING[c.independence]}\n`
  );
}
