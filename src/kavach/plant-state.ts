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

import { existsSync, readFileSync, statSync, readlinkSync, writeFileSync, mkdirSync } from "fs";
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

// Roots are env-overridable so this is not a package that only works on one machine.
//
// The override CANNOT be silent, and that is the whole design. These paths are the
// protected sources: relocating them is precisely the bypass ANU-007 exists to close,
// because an actor who chooses where the instrument lives has chosen what it reads. So
// every refusal and every compile report states when a root is not the default, and the
// resolved paths travel with the verdict. An override that must announce itself is a
// portability feature; a silent one would be a hole.
//
// Defaults are ANKR's own layout. Anyone else sets ANKR_CONFIG_DIR / ANKR_STATE_DIR /
// AEGIS_HOME.

function envRoot(name: string, fallback: string): { path: string; overridden: boolean } {
  const v = process.env[name]?.trim();
  return v ? { path: v.replace(/\/+$/, ""), overridden: true } : { path: fallback, overridden: false };
}

const ANKR_CONFIG_ROOT = envRoot("ANKR_CONFIG_DIR", "/root/.ankr/config");
const ANKR_STATE_ROOT = envRoot("ANKR_STATE_DIR", "/root/.ankr/state");
const AEGIS_ROOT = envRoot("AEGIS_HOME", "/root/.aegis");

const ANKR_STATE = ANKR_STATE_ROOT.path;
const ANKR_CONFIG = ANKR_CONFIG_ROOT.path;
const DATABASES_JSON = `${ANKR_CONFIG}/databases.json`;
const PORTS_JSON = `${ANKR_CONFIG}/ports.json`;
const SESSIONS_JSON = `${ANKR_STATE}/claude-sessions.json`;
const EDIT_HEAT_LEDGER = `${ANKR_STATE}/edit-heat.jsonl`;

export const ANKR_CONFIG_DIR = ANKR_CONFIG;
export const ANKR_STATE_DIR = ANKR_STATE;
export const AEGIS_DIR_PATH = AEGIS_ROOT.path;
export { DATABASES_JSON, PORTS_JSON };

/**
 * Which roots are not the default, so no verdict can rest on a relocated instrument
 * without saying so. @rule:ANU-007
 */
export function overriddenRoots(): string[] {
  const out: string[] = [];
  if (ANKR_CONFIG_ROOT.overridden) out.push(`ANKR_CONFIG_DIR=${ANKR_CONFIG_ROOT.path}`);
  if (ANKR_STATE_ROOT.overridden) out.push(`ANKR_STATE_DIR=${ANKR_STATE_ROOT.path}`);
  if (AEGIS_ROOT.overridden) out.push(`AEGIS_HOME=${AEGIS_ROOT.path}`);
  return out;
}

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

// ── Source integrity (ANU-007) ───────────────────────────────────────────────
//
// From a peer, 2026-09-22: "none of the three should be allowed to quietly
// collapse into the same system."
//
// The permissive layer decides whether an action may proceed by reading files the
// acting agent can write. That is the same defect as a confirming sensor reporting
// through the controller that moved the valve: the instrument and the actor share a
// substrate. `anumati` therefore refuses to trust a state source that shows signs of
// agent authorship, exactly as ANU-004 refuses a source it cannot read at all.
//
// HONEST CEILING: this catches writes that went through an agent tool and makes any
// other tampering leave a record a human must clear. It does not stop a determined
// root process. It raises the rung from "no independence" to "tampering leaves a
// trace", which is a real improvement and is not the same as solving it.

const AEGIS_DIR = AEGIS_ROOT.path;
export const ANUMATI_MODE_FILE = `${AEGIS_DIR}/anumati-mode`;
export const ANUMATI_SEAL_FILE = `${AEGIS_DIR}/anumati-mode.seal.json`;
export const ANUMATI_TAINT_FILE = `${AEGIS_DIR}/anumati-taint.json`;
// AF-T-702 — the tripwire containment instruments are enforcement state too (ANU-007):
// evidence, the human-clear record, and the sealed mode switch all change what bites.
// Sanctioned writers: the hook faces (in-process) and `aegis tripwire-clear|tripwire-mode`.
export const TRIPWIRE_LEDGER_FILE = `${AEGIS_DIR}/tripwire.jsonl`;
export const TRIPWIRE_CLEARS_FILE = `${AEGIS_DIR}/tripwire-clears.json`;
export const TRIPWIRE_MODE_FILE = `${AEGIS_DIR}/tripwire-mode`;
export const TRIPWIRE_MODE_SEAL_FILE = `${AEGIS_DIR}/tripwire-mode.seal.json`;
// AF-T-707 — a publish mandate is a named consent; only `aegis publish-mandate` writes it.
export const PUBLISH_MANDATES_FILE = `${AEGIS_DIR}/publish-mandates.json`;

/** The files the permissive layer's own verdicts depend on — including its own controls.
 *  A layer whose mode switch is writable by the thing it governs has no mode switch. */
export const PROTECTED_SOURCES: readonly string[] = [
  DATABASES_JSON,
  PORTS_JSON,
  SESSIONS_JSON,
  EDIT_HEAT_LEDGER,
  ANUMATI_MODE_FILE,
  ANUMATI_SEAL_FILE,
  ANUMATI_TAINT_FILE,
  TRIPWIRE_LEDGER_FILE,
  TRIPWIRE_CLEARS_FILE,
  TRIPWIRE_MODE_FILE,
  TRIPWIRE_MODE_SEAL_FILE,
  PUBLISH_MANDATES_FILE,
];

export function isProtectedSource(path: string): boolean {
  return PROTECTED_SOURCES.includes(path);
}

export interface TaintRecord {
  path: string;
  detected_at: string;
  detail: string;
}

function readTaintFile(): Record<string, TaintRecord> {
  try {
    if (!existsSync(ANUMATI_TAINT_FILE)) return {};
    return JSON.parse(readFileSync(ANUMATI_TAINT_FILE, "utf-8")) as Record<string, TaintRecord>;
  } catch {
    // An unreadable taint file is itself untrustworthy state. Callers treat the empty
    // result plus the ledger scan below as the live signal; the file is a cache of
    // findings, never the only detector.
    return {};
  }
}

function writeTaintFile(all: Record<string, TaintRecord>): void {
  try {
    mkdirSync(AEGIS_DIR, { recursive: true });
    writeFileSync(ANUMATI_TAINT_FILE, JSON.stringify(all, null, 2));
  } catch {
    /* recording a taint must never itself throw into the gate */
  }
}

/**
 * Protected sources that an agent tool has written, per the shared edit-heat ledger.
 *
 * The ledger records tool-route Edit/Write calls. Machine writers — ankr-ctl, oracle-sync,
 * the self-registry — do not go through Claude tools and so never appear here, which is
 * why this signal distinguishes an agent hand-edit from a legitimate machine write without
 * needing a allowlist of writer binaries.
 *
 * Findings are STICKY: once detected they persist to disk and only a human clears them,
 * the same discipline as KAV-066's LOCKED state.
 */
export function readTaintedSources(): Reading<TaintRecord[]> {
  const persisted = readTaintFile();

  if (existsSync(EDIT_HEAT_LEDGER)) {
    let lines: string[];
    try {
      lines = readFileSync(EDIT_HEAT_LEDGER, "utf-8").trim().split("\n").filter(Boolean);
    } catch (e: any) {
      return unknown(`edit-heat ledger unreadable: ${e?.message}`, EDIT_HEAT_LEDGER);
    }
    let found = false;
    for (const rec of detectTaintInLedger(lines)) {
      if (persisted[rec.path]) continue;
      persisted[rec.path] = rec;
      found = true;
    }
    if (found) writeTaintFile(persisted);
  }

  return known(Object.values(persisted), ANUMATI_TAINT_FILE);
}

/**
 * The detector, as a pure function of ledger lines.
 *
 * Split out from the file read deliberately: it lets the test suite exercise detection
 * against synthetic ledger lines instead of writing to the SHARED edit-heat ledger, which
 * would taint the real configuration for every session on the box. A test environment
 * override would have been the other way to get coverage here, and an override that
 * relocates the protected paths is exactly the bypass ANU-007 exists to close.
 */
export function detectTaintInLedger(lines: string[]): TaintRecord[] {
  const out: TaintRecord[] = [];
  const seen = new Set<string>();
  for (const line of lines) {
    let e: { ts?: number; sid?: string; fp?: string };
    try {
      e = JSON.parse(line);
    } catch {
      continue;
    }
    if (!e.fp || !e.sid || e.sid === "RELEASED") continue;
    if (!isProtectedSource(e.fp)) continue;
    if (seen.has(e.fp)) continue;
    seen.add(e.fp);
    out.push({
      path: e.fp,
      detected_at: new Date(e.ts ?? Date.now()).toISOString(),
      detail: `written through an agent tool by session ${e.sid.slice(0, 8)}`,
    });
  }
  return out;
}

/** Record a taint found by something other than the ledger scan. */
export function recordTaint(path: string, detail: string): void {
  const all = readTaintFile();
  if (all[path]) return;
  all[path] = { path, detected_at: new Date().toISOString(), detail };
  writeTaintFile(all);
}

/** Human release. Mirrors `quarantine release` — a reason is mandatory. */
export function clearTaint(path: string, reason: string): boolean {
  const all = readTaintFile();
  if (!all[path]) return false;
  delete all[path];
  writeTaintFile(all);
  return true;
}

// ── Database endpoints (for coarse projection) ───────────────────────────────

export interface DbEndpoint {
  name: string;
  host: string;
  port: number;
  /** null when the entry carries no class — UNKNOWN, and unknown never means dev. */
  klass: string | null;
}

/**
 * Every database as a network endpoint plus its declared class.
 *
 * The permissive layer reasons in names ("is academy_prod dev-class?"). The kernel reasons
 * in addresses. This reader is the bridge, and it exists so the compiler can discover where
 * the two vocabularies genuinely line up and where they do not.
 */
export function readDatabaseEndpoints(): Reading<DbEndpoint[]> {
  const file = readJson<{
    databases?: Record<string, Record<string, unknown>>;
    servers?: Record<string, { port?: number; host?: string }>;
  }>(DATABASES_JSON, "databases.json");
  if (!file.known) return unknown(file.why, file.source);

  const servers = file.value.servers ?? {};
  const out: DbEndpoint[] = [];

  for (const [name, entry] of Object.entries(file.value.databases ?? {})) {
    if (!entry || typeof entry !== "object") continue;
    const host = String(entry.host ?? entry.server ?? "localhost");
    const declaredPort = entry.port;
    const serverPort = servers[host]?.port;
    const port = typeof declaredPort === "number" ? declaredPort
      : typeof serverPort === "number" ? serverPort
      : 5432; // postgres default — the only guess here, and it is the registry's own default
    const klass = typeof entry.class === "string" && entry.class ? entry.class : null;
    out.push({ name, host, port, klass });
  }

  if (out.length === 0) return unknown("databases.json has no usable entries", DATABASES_JSON);
  return known(out, DATABASES_JSON);
}
