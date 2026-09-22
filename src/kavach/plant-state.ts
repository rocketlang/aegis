// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// KAVACH — Plant State: independent readers of the asset's actual condition
// @rule:ANU-001 A permissive is a pure function of (action, asset, independently-read state)
// @rule:ANU-004 A reader that cannot read returns UNKNOWN — never a guess, never a default
//
// Every function here reads GROUND TRUTH about an asset. None of them read the agent's
// reasoning, the command text, or any declared capability. That separation is the whole
// point: authority is declared, plant state is observed.
//
// Design note — a reader NEVER throws and NEVER substitutes a default on failure. It says
// "I could not read this, and here is why". The permissive layer turns that into a refusal.
// A reader that returns a safe-looking default is how a gate silently stops gating.

import { existsSync, readFileSync, statSync, readlinkSync } from "fs";
import { execFileSync } from "child_process";

// ── Reading ───────────────────────────────────────────────────────────────────

export type Reading<T> =
  | { known: true; value: T; source: string }
  | { known: false; why: string; source: string };

function known<T>(value: T, source: string): Reading<T> {
  return { known: true, value, source };
}

function unknown<T>(why: string, source: string): Reading<T> {
  return { known: false, why, source };
}

// ── Paths (ground truth lives in .ankr, not in aegis) ────────────────────────

const ANKR_STATE = "/root/.ankr/state";
const ANKR_CONFIG = "/root/.ankr/config";
const DATABASES_JSON = `${ANKR_CONFIG}/databases.json`;
const PORTS_JSON = `${ANKR_CONFIG}/ports.json`;
const SESSIONS_JSON = `${ANKR_STATE}/claude-sessions.json`;
const EDIT_HEAT_LEDGER = `${ANKR_STATE}/edit-heat.jsonl`;

/** Same hot window as edit-heat-guard.mjs — this reader shares its ground truth, never forks it. */
export const EDIT_HEAT_TTL_MS = 30 * 60e3;

function readJson<T>(path: string, label: string): Reading<T> {
  if (!existsSync(path)) return unknown(`${label} not present at ${path}`, path);
  try {
    return known(JSON.parse(readFileSync(path, "utf-8")) as T, path);
  } catch (e: any) {
    return unknown(`${label} unreadable: ${e?.message ?? "parse error"}`, path);
  }
}

// ── Database class (ANU-I-001) ───────────────────────────────────────────────

export type DbClass = "dev" | "demo" | "e2e" | "legacy" | "prod" | string;

/**
 * Class of a database as declared in databases.json.
 * An entry with no `class` key is UNKNOWN — not "probably dev". Two of the 80 entries
 * on this box have no class, and a schema op against them must refuse until a human
 * classifies them. @rule:ANU-I-001
 */
export function readDbClass(dbName: string): Reading<DbClass> {
  const file = readJson<{ databases?: Record<string, { class?: string }> }>(DATABASES_JSON, "databases.json");
  if (!file.known) return unknown(file.why, file.source);

  const entry = file.value.databases?.[dbName];
  if (!entry) return unknown(`no entry for database "${dbName}" in databases.json`, DATABASES_JSON);
  if (!entry.class) return unknown(`database "${dbName}" carries no class field`, DATABASES_JSON);
  return known(entry.class, DATABASES_JSON);
}

/** Every database name known to the registry — used to resolve a name out of a command. */
export function readKnownDbNames(): Reading<string[]> {
  const file = readJson<{ databases?: Record<string, unknown> }>(DATABASES_JSON, "databases.json");
  if (!file.known) return unknown(file.why, file.source);
  const names = Object.keys(file.value.databases ?? {});
  if (names.length === 0) return unknown("databases.json has no databases block", DATABASES_JSON);
  return known(names, DATABASES_JSON);
}

// ── File heat (ANU-I-002) ────────────────────────────────────────────────────

export interface FileHolder {
  session_id: string;
  pid: number | null;
  held_for_ms: number;
}

/** A session is live only if its pid exists and is not a zombie. Mirrors edit-heat-guard.mjs. */
function pidAlive(pid: number | null): boolean {
  if (!pid) return false;
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, "utf-8");
    const state = stat.split(") ")[1]?.split(" ")[0];
    return state !== "Z" && state !== undefined;
  } catch {
    return false;
  }
}

/**
 * Which OTHER live sessions hold this file, per the shared edit-heat ledger.
 *
 * edit-heat-guard.mjs remains the canonical enforcer for the Edit/Write tools. This reader
 * exists because that guard is blind to writes that do not come through a tool — the founder
 * documented this himself: "heredoc edits are invisible to the guard". Reading the same two
 * files lets a permissive extend the SAME ground truth to Bash writes, mv, rm and sed -i.
 * @rule:ANU-I-002
 */
export function readFileHolders(absPath: string, selfSessionId: string): Reading<FileHolder[]> {
  const sessions = readJson<Record<string, { pid?: number | null; lastSeen?: number }>>(
    SESSIONS_JSON,
    "claude-sessions.json",
  );
  if (!sessions.known) return unknown(sessions.why, sessions.source);

  if (!existsSync(EDIT_HEAT_LEDGER)) {
    // No ledger yet is a legitimate cold start, not an unreadable state: nobody holds anything.
    return known([], EDIT_HEAT_LEDGER);
  }

  let lines: string[];
  try {
    lines = readFileSync(EDIT_HEAT_LEDGER, "utf-8").trim().split("\n").filter(Boolean);
  } catch (e: any) {
    return unknown(`edit-heat ledger unreadable: ${e?.message}`, EDIT_HEAT_LEDGER);
  }

  const now = Date.now();
  const released = new Set<string>();
  const holders = new Map<string, FileHolder>();

  for (const line of lines) {
    let e: { ts?: number; sid?: string; fp?: string };
    try {
      e = JSON.parse(line);
    } catch {
      continue;
    }
    if (!e.ts || !e.sid || !e.fp) continue;
    if (e.fp !== absPath) continue;
    if (now - e.ts > EDIT_HEAT_TTL_MS) continue;

    // A founder-issued release mutes the file for the rest of the window.
    if (e.sid === "RELEASED") {
      released.add(e.fp);
      continue;
    }
    if (e.sid === selfSessionId) continue;

    const pid = sessions.value[e.sid]?.pid ?? null;
    if (!pidAlive(pid)) continue; // a dead session holds nothing

    holders.set(e.sid, { session_id: e.sid, pid, held_for_ms: now - e.ts });
  }

  if (released.has(absPath)) return known([], EDIT_HEAT_LEDGER);
  return known([...holders.values()], EDIT_HEAT_LEDGER);
}

/**
 * Wall-clock age of the file on disk. Used to catch an UNLEDGERED writer — a process that
 * changed the file without going through any tool. Absent file is a known state (no file).
 */
export function readFileMtimeAgeMs(absPath: string): Reading<number | null> {
  if (!existsSync(absPath)) return known(null, absPath);
  try {
    return known(Date.now() - statSync(absPath).mtimeMs, absPath);
  } catch (e: any) {
    return unknown(`cannot stat ${absPath}: ${e?.message}`, absPath);
  }
}

// ── Shared git index (ANU-I-003) ─────────────────────────────────────────────

/**
 * Paths currently staged in the SHARED git index. On a tree with concurrent sessions the
 * index is shared state: a twin committed five files from another session on 2026-06-11.
 * @rule:ANU-I-003
 */
export function readStagedPaths(repoDir: string): Reading<string[]> {
  try {
    const out = execFileSync("git", ["-C", repoDir, "diff", "--cached", "--name-only"], {
      encoding: "utf-8",
      timeout: 5000,
    });
    return known(out.split("\n").map(s => s.trim()).filter(Boolean), `${repoDir} (git index)`);
  } catch (e: any) {
    return unknown(`cannot read git index in ${repoDir}: ${e?.message}`, repoDir);
  }
}

// ── Port occupancy (ANU-I-004) ───────────────────────────────────────────────

/** `ai-proxy`, `aiProxy` and `ai_proxy` are the same service wearing three spellings. */
function normKey(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]/g, "");
}

/**
 * The port a service is entitled to, per ports.json — the port authority (R-008).
 *
 * ports.json is grouped: `{ group: { serviceKey: port } }`, so `ai-proxy` lives at
 * `ai.proxy`. A service key that resolves to two DIFFERENT ports (e.g. `ankrtms` under
 * both `frontend` and `backend`) is ambiguous, and ambiguity is UNKNOWN — not a coin toss.
 */
export function readDeclaredPort(serviceId: string): Reading<number> {
  const file = readJson<Record<string, unknown>>(PORTS_JSON, "ports.json");
  if (!file.known) return unknown(file.why, file.source);

  const want = normKey(serviceId);
  const matches = new Map<number, string>();

  for (const [group, body] of Object.entries(file.value)) {
    if (group.startsWith("_") || !body || typeof body !== "object") continue;
    for (const [key, port] of Object.entries(body as Record<string, unknown>)) {
      if (key.startsWith("_") || typeof port !== "number") continue;
      // `ai-proxy` → group "ai" + key "proxy"; or a bare key match inside any group.
      if (normKey(group) + normKey(key) === want || normKey(key) === want) {
        matches.set(port, `${group}.${key}`);
      }
    }
  }

  if (matches.size === 0) return unknown(`no port declared for service "${serviceId}" in ports.json`, PORTS_JSON);
  if (matches.size > 1) {
    const where = [...matches.entries()].map(([p, k]) => `${k}=${p}`).join(", ");
    return unknown(`"${serviceId}" resolves to ${matches.size} different ports in ports.json (${where})`, PORTS_JSON);
  }
  return known([...matches.keys()][0], PORTS_JSON);
}

export interface PortOccupant {
  pid: number | null;
  process: string | null;
  /** Full argv of the holder. Almost every ANKR service runs as `bun`/`node`, so the process
   *  NAME never identifies it — the command line does. */
  cmdline: string | null;
  /** Working directory of the holder. Verified 2026-09-22: the process on :4444 has an argv
   *  of `node … src/server.ts` and is identifiable ONLY by its cwd `…/apps/ai-proxy`. */
  cwd: string | null;
}

/**
 * Who actually holds a TCP port RIGHT NOW. Not who ports.json says should hold it —
 * the distinction between declared and observed is the whole reason this file exists.
 */
export function readPortOccupant(port: number): Reading<PortOccupant | null> {
  try {
    const out = execFileSync("ss", ["-lptnH", `sport = :${port}`], { encoding: "utf-8", timeout: 5000 });
    const line = out.trim();
    if (!line) return known(null, `ss :${port}`); // free — a known state, not an unknown one

    const m = /pid=(\d+)/.exec(line);
    const name = /users:\(\("([^"]+)"/.exec(line);
    const pid = m ? Number(m[1]) : null;

    let cmdline: string | null = null;
    let cwd: string | null = null;
    if (pid) {
      // Holder may vanish between ss and these reads — the occupancy still stands, we just
      // learn less about it, and learning less is UNKNOWN, not "probably fine".
      try {
        cmdline = readFileSync(`/proc/${pid}/cmdline`, "utf-8").replace(/\0/g, " ").trim() || null;
      } catch {
        cmdline = null;
      }
      try {
        cwd = readlinkSync(`/proc/${pid}/cwd`);
      } catch {
        cwd = null;
      }
    }

    return known({ pid, process: name ? name[1] : null, cmdline, cwd }, `ss :${port}`);
  } catch (e: any) {
    return unknown(`cannot probe port ${port}: ${e?.message}`, `ss :${port}`);
  }
}
