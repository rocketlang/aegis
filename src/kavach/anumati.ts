// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// KAVACH — Anumati: the permissive layer between authority and actuation
//
// @rule:ANU-001 A permissive is a pure function of (action, asset, independently-read state)
// @rule:ANU-002 Invariants declare what must HOLD, never outcomes to avoid
// @rule:ANU-003 PERMIT only when every applicable permissive permits
// @rule:ANU-004 UNKNOWN state refuses — silence = BLOCK, applied to state
// @rule:ANU-005 A refusal never narrows declared_perm_mask and never touches the gate valve
// @rule:ANU-006 Every permissive cites the house law it compiles
// @rule:ANU-007 A permissive may not trust a state source the acting agent can have written
//
// Authority answers "may this agent ask?". This file answers the second question the plant
// asks on a ship and ANKR never asked: "is the asset in a state where the answer can be yes?"
//
// Nothing here consults the agent's reasoning and no LLM is in the path. FP-018 COMPUTE.

import { existsSync, readFileSync, appendFileSync, mkdirSync } from "fs";
import { createHash } from "crypto";
import { join, isAbsolute, resolve } from "path";
import {
  readDbClass,
  readKnownDbNames,
  readFileHolders,
  readFileMtimeAgeMs,
  readStagedPaths,
  readDeclaredPort,
  readPortOccupant,
  readTaintedSources,
  isProtectedSource,
  PROTECTED_SOURCES,
  ANUMATI_MODE_FILE,
  ANUMATI_SEAL_FILE,
  AEGIS_DIR_PATH,
  overriddenRoots,
  type TaintRecord,
} from "./plant-state";
import { isSqlCapableInvocation, isProvablyReadOnly, sqlTargetVerdict } from "./sql-capability";
import { stageFor as tripwireStageFor } from "../tripwire/enforce";

const TRIPWIRE_LEDGER = join(process.env.HOME || "/root", ".aegis", "tripwire.jsonl");

// ── Types ─────────────────────────────────────────────────────────────────────

export type Verdict = "PERMIT" | "REFUSE" | "UNKNOWN";

export interface ProposedAction {
  tool: string;
  session_id: string;
  cwd: string;
  command?: string;
  file_path?: string;
}

export interface PermissiveResult {
  id: string;
  title: string;
  law: string;
  verdict: Verdict;
  detail: string;
  /** Where the state came from — an assertion with no source is an opinion. */
  source?: string;
  /** "observe" = this result is REPORTED and LEDGERED but never flips the decision to REFUSE.
   *  How a new invariant is introduced without disarming the enforced ones (AF-T-103). */
  stage?: "enforce" | "observe";
}

export interface AnumatiDecision {
  verdict: "PERMIT" | "REFUSE";
  /** Permissives that applied to this action. Non-applicable ones are not evaluated. */
  results: PermissiveResult[];
  /** Enforcing (non-observe) results that were not PERMIT — these set the verdict. */
  refusals: PermissiveResult[];
  /** Observe-stage results that were not PERMIT — reported and ledgered, never blocking. */
  observations: PermissiveResult[];
  evaluated_at: string;
}

interface Permissive {
  id: string;
  title: string;
  law: string;
  /** default "enforce". "observe" stages the WHOLE invariant: it reports/ledgers, never blocks.
   *  A check() may instead return a per-verdict stage, which wins — so one invariant can enforce
   *  its high-confidence branch and observe its low-confidence one (AF-R-005 graded promotion). */
  stage?: "enforce" | "observe";
  applies(a: ProposedAction): boolean;
  check(a: ProposedAction): { verdict: Verdict; detail: string; source?: string; stage?: "enforce" | "observe" };
}

// ── Mode (ANU-YK-001) ─────────────────────────────────────────────────────────

export type AnumatiMode = "shadow" | "enforce";

export interface ModeStatus {
  mode: AnumatiMode;
  /** false when the mode file and its seal disagree, or no seal exists yet. */
  sealed: boolean;
  note: string | null;
}

/** enforce is stricter than shadow. Used when the mode file and its seal disagree. */
function stricter(a: AnumatiMode, b: AnumatiMode): AnumatiMode {
  return a === "enforce" || b === "enforce" ? "enforce" : "shadow";
}

/**
 * The mode, and whether it can be trusted.
 *
 * @rule:ANU-007 — the mode switch is itself a protected state source. A layer whose
 * off-switch is writable by the thing it governs has no off-switch, so the value is
 * sealed: `aegis anumati mode` writes both the file and a hash of it. If they disagree,
 * the STRICTER of the two wins. That cannot brick anything, because the sealed value was
 * set by a human, and it means downgrading enforcement takes two coordinated writes
 * instead of one and leaves a mismatch behind either way.
 */
export function anumatiModeStatus(): ModeStatus {
  const env = process.env.ANUMATI_MODE;
  if (env === "enforce" || env === "shadow") {
    return { mode: env, sealed: false, note: "set by ANUMATI_MODE in this process environment" };
  }

  let fileMode: AnumatiMode | null = null;
  let fileHash: string | null = null;
  try {
    if (existsSync(ANUMATI_MODE_FILE)) {
      const raw = readFileSync(ANUMATI_MODE_FILE, "utf-8");
      const v = raw.trim();
      if (v === "enforce" || v === "shadow") {
        fileMode = v;
        fileHash = createHash("sha256").update(raw).digest("hex");
      }
    }
  } catch {
    /* treated as absent below */
  }

  let seal: { mode?: string; sha256?: string } | null = null;
  try {
    if (existsSync(ANUMATI_SEAL_FILE)) seal = JSON.parse(readFileSync(ANUMATI_SEAL_FILE, "utf-8"));
  } catch {
    seal = null;
  }

  if (fileMode === null) {
    // No usable mode file. If a seal survives, honour what the human last set.
    if (seal?.mode === "enforce" || seal?.mode === "shadow") {
      return { mode: seal.mode, sealed: false, note: "mode file missing or unreadable — using the last sealed value" };
    }
    return { mode: "shadow", sealed: false, note: "no mode set — defaulting to shadow" };
  }

  if (!seal?.sha256) {
    return { mode: fileMode, sealed: false, note: "mode file is unsealed — set it via `aegis anumati mode` to seal it" };
  }

  if (seal.sha256 === fileHash) {
    return { mode: fileMode, sealed: true, note: null };
  }

  const sealMode: AnumatiMode = seal.mode === "enforce" ? "enforce" : "shadow";
  const effective = stricter(fileMode, sealMode);
  return {
    mode: effective,
    sealed: false,
    note: `SEAL MISMATCH — mode file says ${fileMode}, seal says ${sealMode}; using the stricter (${effective})`,
  };
}

/**
 * shadow: report, never block. enforce: refusals bite.
 * Shadow is LOUD by design — a silent shadow is a guard that has already decayed.
 */
export function anumatiMode(): AnumatiMode {
  return anumatiModeStatus().mode;
}

// ── Action-shape helpers ──────────────────────────────────────────────────────

function abs(p: string, cwd: string): string {
  return isAbsolute(p) ? p : resolve(cwd, p);
}

/** Strip quotes a shell would strip, so `> "a b.txt"` resolves to the real path. */
function unquote(s: string): string {
  return s.replace(/^['"]|['"]$/g, "");
}

/**
 * Write targets a Bash command would touch. Deliberately conservative: only shapes whose
 * target position is unambiguous. A shape we do not recognise yields nothing here and is
 * handled by the recogniser below, never silently treated as harmless.
 */
export function bashWriteTargets(command: string, cwd: string): string[] {
  const out = new Set<string>();
  const add = (p?: string) => {
    if (p) out.add(abs(unquote(p), cwd));
  };

  for (const m of command.matchAll(/(?:^|[^>\d])>>?\s*(['"]?[^\s'"|&;<>]+['"]?)/g)) add(m[1]);
  for (const m of command.matchAll(/\bsed\s+(?:-[^\s]*\s+)*-i[^\s]*\s+(?:(?:-e\s+)?\S+\s+)?(['"]?[^\s'"|&;]+['"]?)/g)) add(m[1]);
  for (const m of command.matchAll(/\btee\s+(?:-a\s+)?(['"]?[^\s'"|&;]+['"]?)/g)) add(m[1]);
  for (const m of command.matchAll(/\bmv\s+(?:-\S+\s+)*\S+\s+(['"]?[^\s'"|&;]+['"]?)/g)) add(m[1]);
  for (const m of command.matchAll(/\brm\s+(?:-\S+\s+)*(['"]?[^\s'"|&;]+['"]?)/g)) add(m[1]);
  for (const m of command.matchAll(/\btruncate\s+(?:-\S+\s+)*(['"]?[^\s'"|&;]+['"]?)/g)) add(m[1]);

  return [...out];
}

const SCHEMA_PATTERNS: RegExp[] = [
  /\bprisma\s+db\s+push\b/i,
  /\bprisma\s+migrate\s+(dev|deploy|reset)\b/i,
  /\bDROP\s+(TABLE|SCHEMA|DATABASE|COLUMN)\b/i,
  /\bALTER\s+TABLE\b[\s\S]*\b(DROP|RENAME|ALTER\s+COLUMN)\b/i,
  /\bTRUNCATE\s+(TABLE\s+)?\w/i,
  /\bDELETE\s+FROM\b(?![\s\S]*\bWHERE\b)/i,
];

export function isSchemaTouching(command: string): boolean {
  return SCHEMA_PATTERNS.some(re => re.test(command));
}

/**
 * Best-effort resolution of WHICH database a command targets. Returns null when it cannot be
 * resolved — and under ANU-004 "cannot resolve" refuses a schema op rather than waving it past.
 */
export function resolveTargetDb(command: string): string | null {
  // Explicit target wins, in psql's own precedence: -d/--dbname, then a connection URL.
  const dbFlag = /(?:^|\s)(?:-d|--dbname[= ])\s*(['"]?)([A-Za-z0-9_]+)\1/.exec(command);
  if (dbFlag) return dbFlag[2];

  const url = /postgres(?:ql)?:\/\/[^\s'"]*\/([A-Za-z0-9_]+)/.exec(command);
  if (url) return url[1];

  // AF-T-106 — an inline `PGDATABASE=<name>` assignment IS the connection target when no -d
  // is given. Only a literal alnum/underscore name resolves; `PGDATABASE=$VAR` does not match
  // and stays null → UNKNOWN → refuse/observe (INF-AFW-004). This can only NAME a target more
  // often, never mis-route: PGDATABASE is exactly what psql connects to. @rule:AFW-YK-002
  const pgEnv = /(?:^|\s)PGDATABASE=(['"]?)([A-Za-z0-9_]+)\1/.exec(command);
  if (pgEnv) return pgEnv[2];

  const names = readKnownDbNames();
  if (names.known) {
    // Longest match first: `ankr_core_dev` must win over `ankr_core`.
    const hit = [...names.value].sort((a, b) => b.length - a.length)
      .find(n => new RegExp(`\\b${n}\\b`).test(command));
    if (hit) return hit;
  }
  return null;
}

// ── The invariants ────────────────────────────────────────────────────────────

const PERMISSIVES: Permissive[] = [
  {
    id: "ANU-I-001",
    title: "Schema-touching op only where the database class is dev",
    law: "R-005/R-006/R-010 — Database Destruction Prevention (GOSPEL)",
    applies: a => a.tool === "Bash" && !!a.command && isSchemaTouching(a.command),
    check: a => {
      const db = resolveTargetDb(a.command!);
      if (!db) {
        return {
          verdict: "UNKNOWN",
          detail: "schema-touching command whose target database cannot be resolved",
          source: "command text + databases.json",
        };
      }
      const cls = readDbClass(db);
      if (!cls.known) return { verdict: "UNKNOWN", detail: `${db}: ${cls.why}`, source: cls.source };
      if (cls.value !== "dev") {
        return {
          verdict: "REFUSE",
          detail: `${db} is class=${cls.value} — schema ops are permitted only on dev-class databases`,
          source: cls.source,
        };
      }
      return { verdict: "PERMIT", detail: `${db} is class=dev`, source: cls.source };
    },
  },

  {
    id: "ANU-I-002",
    title: "Target file is held by no other live session",
    law: "Multi-Agent Coexistence — Edit-Heat Guard (2026-06-11 twin-resume incident)",
    applies: a => {
      if (a.file_path) return true;
      return a.tool === "Bash" && !!a.command && bashWriteTargets(a.command, a.cwd).length > 0;
    },
    check: a => {
      const targets = a.file_path
        ? [abs(a.file_path, a.cwd)]
        : bashWriteTargets(a.command!, a.cwd);

      for (const t of targets) {
        const holders = readFileHolders(t, a.session_id);
        if (!holders.known) return { verdict: "UNKNOWN", detail: `${t}: ${holders.why}`, source: holders.source };

        if (holders.value.length > 0) {
          const h = holders.value[0];
          const mins = Math.round(h.held_for_ms / 60e3);
          return {
            verdict: "REFUSE",
            detail: `${t} is held by live session ${h.session_id.slice(0, 8)} (pid ${h.pid}, ${mins}m ago)`,
            source: holders.source,
          };
        }

        // Deliberately NOT refusing on a fresh mtime alone.
        //
        // An unledgered recent write says a write happened. It cannot say that another
        // LIVE SESSION HOLDS the file, which is what this invariant asserts — and it
        // cannot distinguish another session's write from this session's own, since a
        // shell redirect or heredoc never reaches the ledger either. Measured before
        // enforcement was switched on: it refused ordinary edits to files this very
        // session had just written by script. That is the wrong instrument for the
        // question, not a threshold to tune.
        //
        // The ledger is the authoritative evidence and is used above. For the tool path,
        // edit-heat-guard.mjs keeps its own mtime HOLD, which is one-time and has a
        // documented release; this layer does not duplicate it without one.
      }
      return { verdict: "PERMIT", detail: `${targets.length} target(s) held by nobody`, source: "edit-heat ledger" };
    },
  },

  {
    id: "ANU-I-003",
    title: "Shared git index holds nothing this session did not stage",
    law: "Multi-Agent Coexistence — the git INDEX is shared; use pathspec commits",
    applies: a =>
      a.tool === "Bash" &&
      !!a.command &&
      /\bgit\s+(?:-C\s+\S+\s+)?commit\b/.test(a.command) &&
      !/\bgit\s+(?:-C\s+\S+\s+)?commit\b[^|&;]*\s--\s/.test(a.command),
    check: a => {
      const staged = readStagedPaths(a.cwd);
      if (!staged.known) return { verdict: "UNKNOWN", detail: staged.why, source: staged.source };
      if (staged.value.length === 0) {
        return { verdict: "PERMIT", detail: "shared index is empty", source: staged.source };
      }
      // A commit with no `--` pathspec sweeps whatever the index holds — including another
      // session's staged files. Proven on 2026-06-11.
      return {
        verdict: "REFUSE",
        detail:
          `shared git index holds ${staged.value.length} staged path(s) and this commit carries no ` +
          `\`--\` pathspec — it would sweep them: ${staged.value.slice(0, 5).join(", ")}` +
          (staged.value.length > 5 ? ` (+${staged.value.length - 5} more)` : ""),
        source: staged.source,
      };
    },
  },

  {
    id: "ANU-I-004",
    title: "Declared port is free, or already held by this same service",
    law: "R-008 Port Authority — port drift is silent",
    applies: a => a.tool === "Bash" && !!a.command && /\bankr-ctl\s+(start|restart)\s+\S/.test(a.command),
    check: a => {
      const m = /\bankr-ctl\s+(?:start|restart)\s+(['"]?)([A-Za-z0-9._-]+)\1/.exec(a.command!);
      if (!m) return { verdict: "UNKNOWN", detail: "cannot resolve service id from ankr-ctl command" };

      const svc = m[2];
      const port = readDeclaredPort(svc);
      if (!port.known) return { verdict: "UNKNOWN", detail: `${svc}: ${port.why}`, source: port.source };

      const occ = readPortOccupant(port.value);
      if (!occ.known) return { verdict: "UNKNOWN", detail: `${svc}: ${occ.why}`, source: occ.source };
      if (occ.value === null) {
        return { verdict: "PERMIT", detail: `port ${port.value} is free`, source: occ.source };
      }
      // Occupied by this same service = a restart, which is the point of `restart`.
      // The process NAME is useless here — nearly everything on this box is `bun` or `node`.
      // The argv is what identifies a service, so that is what we match.
      const occupant = occ.value;
      // Identity lives in argv OR in the working directory. Verified on this box: the holder
      // of :4444 has argv `node … src/server.ts` and is only identifiable by cwd `…/ai-proxy`.
      const fingerprint = [occupant.cmdline, occupant.cwd].filter(Boolean).join(" ");
      if (!fingerprint) {
        return {
          verdict: "UNKNOWN",
          detail: `port ${port.value} is held by pid ${occupant.pid} whose argv and cwd cannot be read — cannot tell whether it is ${svc}`,
          source: occ.source,
        };
      }
      if (fingerprint.includes(svc)) {
        return {
          verdict: "PERMIT",
          detail: `port ${port.value} already held by ${svc} itself (pid ${occupant.pid}) — this is a restart`,
          source: occ.source,
        };
      }
      return {
        verdict: "REFUSE",
        detail:
          `port ${port.value} (declared for ${svc}) is held by pid ${occupant.pid} ` +
          `(${occupant.process ?? "unnamed"} in ${occupant.cwd ?? "unknown cwd"}) — ` +
          `starting ${svc} would bind the wrong service or fail silently`,
        source: occ.source,
      };
    },
  },

  {
    id: "ANU-I-005",
    title: "The permissive layer's own state sources are not hand-written by the agent",
    law: "config is machine-owned — route via ankr-ctl / oracle-sync, never a hand edit",
    applies: a => writeTargetsOf(a).some(isProtectedSource),
    check: a => {
      const hit = writeTargetsOf(a).filter(isProtectedSource);
      return {
        verdict: "REFUSE",
        detail:
          `this action writes ${hit.length} file(s) the permissive layer reads its own verdicts from ` +
          `(${hit.join(", ")}) — an instrument the actor can edit is not an instrument. ` +
          `Route the change through its owning tool.`,
        source: "protected source list",
      };
    },
  },

  {
    // AF-T-103 — the semantic gate that closes the red-team's regex-ceiling gaps. It does not
    // read the SQL text (a quote-split keyword or a $VAR statement defeats that); it asks
    // whether an arbitrary-SQL invocation is aimed at a non-dev database and cannot be proven
    // read-only. Complements the lexical check-destructive gate — two gates, two jobs.
    //
    // GRADED PROMOTION (AF-R-005, 2026-09-24): the shadow ledger held no real evidence, only
    // synthetic test entries. So the branch we can be SURE of — a target RESOLVED to a non-dev
    // class — now ENFORCES (we positively identified prod). The branch where false positives
    // live — an UNRESOLVABLE target (a legit dev write via $PGDATABASE would land here) — stays
    // OBSERVE via a per-verdict stage until the ledger justifies enforcing it. @rule:FP-018
    id: "ANU-I-006",
    title: "Arbitrary-SQL invocation against a non-dev target (statement not provably read-only)",
    law: "FP-018 semantic gate — gate on the resolved target's capability, not the command text",
    applies: a =>
      a.tool === "Bash" && !!a.command &&
      isSqlCapableInvocation(a.command) && !isProvablyReadOnly(a.command),
    check: a => sqlTargetVerdict(a.command!, resolveTargetDb, readDbClass),
  },

  {
    // AF-T-702 — a principal the tripwire ladder has QUARANTINED (or revoked) does not act.
    // The evidence and the stage live in the tripwire layer; this permissive only READS the
    // stage and refuses — it never touches the valve (ANU-005: refusal and actuation are
    // separate axes). De-escalation is human-only: `aegis tripwire-clear <principal>`.
    // IDs ANU-I-007/-008 stay reserved for the egress/filesystem permissives designed in
    // AF-T-108. Ships observe (AFW-006); promotion is a founder call on ledger evidence.
    id: "ANU-I-009",
    title: "Acting principal is not quarantined by the tripwire containment ladder",
    law: "AFW-011 staged containment — quarantine isolates; only a human clears",
    stage: "observe",
    applies: a => {
      // Cheap gate: no tripwire ledger, or this session never appears in it → not applicable.
      try {
        return existsSync(TRIPWIRE_LEDGER) && readFileSync(TRIPWIRE_LEDGER, "utf-8").includes(a.session_id);
      } catch { return false; }
    },
    check: a => {
      const { decision, hits, distinctKinds } = tripwireStageFor(a.session_id);
      if (decision.stage === "quarantine" || decision.stage === "revoke") {
        return {
          verdict: "REFUSE",
          detail:
            `principal ${a.session_id.slice(0, 12)} is at containment stage ${decision.stage} ` +
            `(${hits} tripwire hit(s), ${distinctKinds} kind(s)) — ${decision.reason}. ` +
            `A human clears it: aegis tripwire-clear ${a.session_id} --reason "..."`,
          source: "tripwire.jsonl + tripwire-clears.json",
        };
      }
      return {
        verdict: "PERMIT",
        detail: `containment stage ${decision.stage} — below quarantine, action permitted`,
        source: "tripwire.jsonl + tripwire-clears.json",
      };
    },
  },
];

/** Files this action would write: the Write/Edit target, or whatever a Bash command redirects into. */
function writeTargetsOf(a: ProposedAction): string[] {
  if (a.file_path) return [abs(a.file_path, a.cwd)];
  if (a.tool === "Bash" && a.command) return bashWriteTargets(a.command, a.cwd);
  return [];
}

// ── The layer ─────────────────────────────────────────────────────────────────

/**
 * Evaluate every applicable permissive against independently-read plant state.
 * @rule:ANU-003 one REFUSE refuses · @rule:ANU-004 one UNKNOWN refuses
 */
export function anumati(action: ProposedAction): AnumatiDecision {
  const results: PermissiveResult[] = [];

  // @rule:ANU-007 — computed ONCE per evaluation and applied at this single choke point,
  // so a permissive added later cannot forget to ask whether its instrument was tampered
  // with. A verdict read from a tainted source is downgraded to UNKNOWN, which refuses.
  const taintReading = readTaintedSources();
  const tainted = new Map<string, TaintRecord>(
    taintReading.known ? taintReading.value.map(t => [t.path, t]) : [],
  );

  for (const p of PERMISSIVES) {
    let applies = false;
    try {
      applies = p.applies(action);
    } catch {
      // A permissive that cannot even decide whether it applies is itself unknown state.
      results.push({
        id: p.id,
        title: p.title,
        law: p.law,
        stage: p.stage ?? "enforce",
        verdict: "UNKNOWN",
        detail: "applicability could not be determined",
      });
      continue;
    }
    if (!applies) continue;

    const stage = p.stage ?? "enforce";
    try {
      const r = p.check(action);
      // A per-verdict stage from check() wins over the permissive default (graded promotion).
      results.push({ id: p.id, title: p.title, law: p.law, ...r, stage: r.stage ?? stage });
    } catch (e: any) {
      results.push({
        id: p.id,
        title: p.title,
        law: p.law,
        stage,
        verdict: "UNKNOWN",
        detail: `permissive threw: ${e?.message ?? "unknown error"}`,
      });
    }
  }

  // Downgrade any verdict that rests on a compromised instrument.
  const guarded = results.map(r => {
    if (!r.source) return r;
    const t = tainted.get(r.source);
    if (!t) return r;
    return {
      ...r,
      verdict: "UNKNOWN" as Verdict,
      detail: `state source ${r.source} is tainted — ${t.detail} (${t.detected_at}). Cleared only by a human: aegis anumati clear <path> --reason "..."`,
    };
  });
  if (!taintReading.known) {
    guarded.push({
      id: "ANU-007",
      title: "State-source integrity could not be established",
      law: "ANU-007 — a permissive may not trust a source the actor can have written",
      stage: "enforce",
      verdict: "UNKNOWN",
      detail: taintReading.why,
      source: taintReading.source,
    });
  }
  results.length = 0;
  results.push(...guarded);

  // Only ENFORCE-stage non-PERMIT results set the verdict. Observe-stage results are staged
  // in: reported and ledgered, never blocking — the safe way to introduce a new invariant
  // while the enforced ones keep biting. @rule:AF-T-103
  const notPermitted = results.filter(r => r.verdict !== "PERMIT");
  const refusals = notPermitted.filter(r => (r.stage ?? "enforce") !== "observe");
  const observations = notPermitted.filter(r => (r.stage ?? "enforce") === "observe");
  return {
    verdict: refusals.length === 0 ? "PERMIT" : "REFUSE",
    results,
    refusals,
    observations,
    evaluated_at: new Date().toISOString(),
  };
}

// ── Ledger ────────────────────────────────────────────────────────────────────

const LEDGER_DIR = AEGIS_DIR_PATH;
const LEDGER = join(LEDGER_DIR, "anumati.jsonl");

/** Every refusal is recorded, in shadow exactly as in enforce — and so is every observe-stage
 *  would-refuse, even when the overall verdict is PERMIT, so a staged invariant collects its
 *  shadow evidence for the promotion decision. A clean PERMIT with nothing observed is not logged. */
export function ledgerAnumati(action: ProposedAction, decision: AnumatiDecision, mode: AnumatiMode): void {
  if (decision.refusals.length === 0 && decision.observations.length === 0) return;
  try {
    mkdirSync(LEDGER_DIR, { recursive: true });
    appendFileSync(
      LEDGER,
      JSON.stringify({
        ts: decision.evaluated_at,
        mode,
        enforced: mode === "enforce" && decision.refusals.length > 0,
        session: action.session_id,
        tool: action.tool,
        target: action.file_path ?? action.command?.slice(0, 300) ?? null,
        refusals: decision.refusals.map(r => ({ id: r.id, verdict: r.verdict, detail: r.detail })),
        observations: decision.observations.map(r => ({ id: r.id, verdict: r.verdict, detail: r.detail })),
      }) + "\n",
    );
  } catch {
    // A ledger write must never itself block an action.
  }
}

/** Human-readable refusal, in the house's plain-English style. */
export function renderRefusal(decision: AnumatiDecision, mode: AnumatiMode): string {
  const head =
    mode === "enforce"
      ? "[ANUMATI] REFUSED — the plant is not in a state to obey"
      : "[ANUMATI] shadow: WOULD REFUSE — the plant is not in a state to obey";

  const lines = decision.refusals.map(r => {
    const tag = r.verdict === "UNKNOWN" ? "UNKNOWN STATE" : "INVARIANT VIOLATED";
    return `  ${r.id} ${tag}\n    ${r.title}\n    ${r.detail}\n    law: ${r.law}${r.source ? `\n    read: ${r.source}` : ""}`;
  });

  const tail =
    mode === "enforce"
      ? "\n[ANUMATI] Authority is unchanged (ANU-005). Resolve the plant state, then ask again.\n"
      : "\n[ANUMATI] shadow mode — not blocking. Promote with: aegis anumati mode enforce\n";

  // @rule:ANU-007 — a verdict resting on a relocated instrument says so. Whoever chose
  // where the instrument lives chose what it reads, and that must never be invisible.
  const roots = overriddenRoots();
  const rootLine = roots.length
    ? `[ANUMATI] NOTE — non-default state roots in use: ${roots.join(", ")}\n`
    : "";

  return `\n${head}\n${lines.join("\n")}\n${tail}${rootLine}`;
}
