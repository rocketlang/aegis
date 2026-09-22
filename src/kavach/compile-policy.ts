// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// KAVACH — the compiler between the two faces of the permissive layer.
//
// @rule:ANU-008 The coarse policy is COMPILED from the fine invariants, never hand-written
// @rule:ANU-009 A fine invariant that cannot be projected is reported, never silently dropped
// @rule:ANU-010 Drift between compiled and on-disk coarse policy is a compiler bug
//
// The fine face (anumati) reasons in domain vocabulary: "is this a schema operation against
// a database whose registry class is dev?" It is rich, and it only binds an agent that calls
// it. The mandatory face reasons in kernel vocabulary: binary paths, hosts, ports. It binds
// anything, including an agent that never heard of us, and it is necessarily coarser.
//
// Writing those two by hand in two vocabularies guarantees they drift and guarantees nobody
// can say which one is lying. So the coarse one is derived here, mechanically, from the same
// declarations the fine one reads.
//
// The most important output of this file is NOT the policy. It is the coverage report: which
// fine invariants survive projection into kernel vocabulary and which do not. An invariant
// that does not survive binds cooperative agents only, and that is a fact an operator needs
// stated rather than discovered.

import { createHash } from "crypto";
import { readDatabaseEndpoints, readDeclaredPort, PROTECTED_SOURCES, overriddenRoots, type DbEndpoint } from "./plant-state";
import { buildEgressPolicy, type EgressEntry } from "../kernel/egress-policy";
import { existsSync, readFileSync } from "fs";
import { compileDbProxy, DBPROXY_INI } from "./compile-dbproxy";

// ── Types ─────────────────────────────────────────────────────────────────────

/** How completely a fine invariant survives translation into kernel vocabulary. */
export type Projection = "projected" | "partial" | "none";

export interface CoverageEntry {
  invariant: string;
  title: string;
  projection: Projection;
  detail: string;
  /** Number of coarse rules this invariant produced. */
  emitted: number;
}

export interface DenyEntry {
  host: string;
  port: number;
  invariant: string;
  reason: string;
}

export interface CompileNote {
  kind: "substitution" | "conflict" | "ambiguity";
  detail: string;
}

export interface CoarsePolicy {
  agent_id: string;
  domain: string;
  trust_mask: number;
  generated_at: string;
  /** Digest of the declarations this was compiled from. @rule:ANU-010 */
  input_digest: string;
  egress_allow: EgressEntry[];
  egress_deny: DenyEntry[];
  write_deny: Array<{ path: string; invariant: string }>;
  coverage: CoverageEntry[];
  /** Invariants that bind cooperative agents only. The honest headline. */
  unbound_by_coarse: string[];
  notes: CompileNote[];
  /** Non-default state roots this was compiled against. @rule:ANU-007 */
  state_roots_overridden: string[];
}

export interface CompileOptions {
  agentId: string;
  domain: string;
  trustMask: number;
  /** Loopback ports an agent legitimately needs, used when narrowing the wildcard. */
  loopbackPorts?: number[];
}

// ── Endpoint grouping ─────────────────────────────────────────────────────────

interface EndpointGroup {
  host: string;
  port: number;
  members: DbEndpoint[];
  classes: Set<string | null>;
}

function groupByEndpoint(dbs: DbEndpoint[]): EndpointGroup[] {
  const map = new Map<string, EndpointGroup>();
  for (const db of dbs) {
    const key = `${db.host}:${db.port}`;
    let g = map.get(key);
    if (!g) {
      g = { host: db.host, port: db.port, members: [], classes: new Set() };
      map.set(key, g);
    }
    g.members.push(db);
    g.classes.add(db.klass);
  }
  return [...map.values()].sort((a, b) => a.host.localeCompare(b.host) || a.port - b.port);
}

/**
 * Whether an endpoint can carry ANU-I-001 at all.
 *
 * The fine invariant permits schema operations only against dev-class databases. Projected to
 * an address, that is answerable only when every database at the address agrees:
 *   all dev            → the address may be reached
 *   none dev           → the address may be denied
 *   mixed, or unknown  → the address cannot express the invariant at any granularity the
 *                        kernel has, because the permitted and forbidden databases share it
 */
function classify(g: EndpointGroup): "all-dev" | "none-dev" | "mixed" {
  const hasDev = g.members.some(m => m.klass === "dev");
  const hasNonDev = g.members.some(m => m.klass !== "dev"); // null counts as non-dev (ANU-004)
  if (hasDev && hasNonDev) return "mixed";
  return hasDev ? "all-dev" : "none-dev";
}

// ── The compiler ──────────────────────────────────────────────────────────────

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "::1", "localhost"]);

export function compilePolicy(opts: CompileOptions): CoarsePolicy {
  const { agentId, domain, trustMask } = opts;
  const coverage: CoverageEntry[] = [];
  const notes: CompileNote[] = [];
  const egressDeny: DenyEntry[] = [];
  const writeDeny: Array<{ path: string; invariant: string }> = [];

  // Base coarse policy — the kernel's own generator, not a reimplementation of it.
  const base = buildEgressPolicy(trustMask, domain);
  let egressAllow: EgressEntry[] = [...base.allow];

  // ── ANU-I-001 → egress ──────────────────────────────────────────────────────
  const dbs = readDatabaseEndpoints();
  if (!dbs.known) {
    coverage.push({
      invariant: "ANU-I-001",
      title: "Schema-touching op only where the database class is dev",
      projection: "none",
      detail: `database registry unreadable (${dbs.why}) — nothing can be projected, and under ANU-004 that is a refusal to claim coverage, not a claim of none needed`,
      emitted: 0,
    });
  } else {
    // Is the dev-only door in place? If dev-class databases have an address of their own,
    // every shared database address can be denied outright and ANU-I-001 finally projects.
    // The door must be BUILT and CURRENT — a stale config would deny the shared ports while
    // routing dev nowhere, which breaks dev access instead of protecting production.
    let door: { port: number } | null = null;
    let doorNote: string | null = null;
    const dp = compileDbProxy();
    if (!("error" in dp)) {
      if (!existsSync(DBPROXY_INI)) {
        doorNote = `a dev-only door is compilable on port ${dp.plan.listenPort} but has not been generated — run \`aegis anumati dbproxy --apply\` to make ANU-I-001 projectable`;
      } else if (readFileSync(DBPROXY_INI, "utf-8") !== dp.plan.ini) {
        doorNote = `the dev-only door at ${DBPROXY_INI} is STALE — it no longer matches databases.json, so the shared database ports stay allowed rather than denying dev its own route`;
      } else {
        door = { port: dp.plan.listenPort };
      }
    }

    const groups = groupByEndpoint(dbs.value);
    const mixed = groups.filter(g => classify(g) === "mixed");
    let emitted = 0;

    if (door) {
      // Every database address is denied; dev is reached through the door instead.
      for (const g of groups) {
        egressDeny.push({
          host: g.host,
          port: g.port,
          invariant: "ANU-I-001",
          reason: `dev-class databases are reachable through the dev-only door on 127.0.0.1:${door.port}; direct database addresses are denied`,
        });
        emitted++;
      }
      if (!(opts.loopbackPorts ?? []).includes(door.port)) {
        (opts.loopbackPorts ??= []).push(door.port);
      }
      notes.push({
        kind: "substitution",
        detail:
          `dev-only door on 127.0.0.1:${door.port} carries ${dp.plan.exposed.length} dev-class database(s), ` +
          `so all ${emitted} database address(es) are denied outright — including the shared ones where dev and ` +
          `production were previously indistinguishable. Production keeps its address for every non-agent client.`,
      });
      coverage.push({
        invariant: "ANU-I-001",
        title: "Schema-touching op only where the database class is dev",
        projection: "projected",
        detail:
          `${emitted} address(es) denied; dev reached only through the dev-only door. The invariant now binds an ` +
          `agent that never called the permissive layer, because permitted and forbidden databases no longer share an address.`,
        emitted,
      });
    } else {

    for (const g of groups) {
      const verdict = classify(g);
      if (verdict === "none-dev") {
        egressDeny.push({
          host: g.host,
          port: g.port,
          invariant: "ANU-I-001",
          reason: `no dev-class database at this address (${g.members.length}: ${g.members.map(m => `${m.name}=${m.klass ?? "unclassed"}`).slice(0, 4).join(", ")})`,
        });
        emitted++;
      } else if (verdict === "mixed") {
        const devs = g.members.filter(m => m.klass === "dev").map(m => m.name);
        const others = g.members.filter(m => m.klass !== "dev");
        notes.push({
          kind: "ambiguity",
          detail:
            `${g.host}:${g.port} carries both dev and non-dev databases ` +
            `(${devs.length} dev, ${others.length} non-dev incl. ${[...new Set(others.map(m => m.klass ?? "unclassed"))].join("/")}) — ` +
            `ANU-I-001 cannot be expressed at this address because the permitted and forbidden ` +
            `databases are the same endpoint`,
        });
      }
    }

      coverage.push({
        invariant: "ANU-I-001",
        title: "Schema-touching op only where the database class is dev",
        projection: mixed.length > 0 ? "partial" : "projected",
        detail:
          (mixed.length > 0
            ? `${emitted} address(es) denied; ${mixed.length} address(es) carry dev and non-dev databases together and cannot express this invariant at kernel granularity. Separating them needs a distinct port, host or proxy — an infrastructure change, not a code change.`
            : `${emitted} address(es) denied; every address resolves to a single policy`) +
          (doorNote ? ` — ${doorNote}` : ""),
        emitted,
      });
      if (doorNote) notes.push({ kind: "conflict", detail: doorNote });
    }

    // A loopback wildcard readmits everything just denied. Say so, and narrow it.
    // EVERY such entry, not the first: the base policy carries both `localhost:0` and
    // `127.0.0.1:0`, and leaving either one behind re-permits the whole of loopback —
    // which is precisely the decorative-deny failure this compiler exists to catch.
    const wildcards = egressAllow.filter(e => LOOPBACK_HOSTS.has(e.host) && e.port === 0);
    const loopbackDenies = egressDeny.filter(d => LOOPBACK_HOSTS.has(d.host));
    if (wildcards.length > 0 && loopbackDenies.length > 0) {
      const needed = new Set(opts.loopbackPorts ?? []);
      for (const d of loopbackDenies) needed.delete(d.port);

      if (needed.size > 0) {
        const hosts = [...new Set(wildcards.map(w => w.host))];
        egressAllow = egressAllow.filter(e => !(LOOPBACK_HOSTS.has(e.host) && e.port === 0));
        for (const host of hosts) {
          for (const p of [...needed].sort((a, b) => a - b)) {
            egressAllow.push({ host, port: p, note: `loopback ${p} (narrowed from wildcard)` });
          }
        }
        notes.push({
          kind: "substitution",
          detail:
            `replaced ${wildcards.length} any-port loopback allow(s) (${hosts.join(", ")}) with ` +
            `${needed.size} explicit port(s) each: the wildcards admitted every locally denied endpoint, ` +
            `which would have made ${loopbackDenies.length} deny rule(s) decorative`,
        });
      } else {
        notes.push({
          kind: "conflict",
          detail:
            `${wildcards.length} loopback host(s) allowed on any port and no explicit loopback port list was ` +
            `supplied, so ${loopbackDenies.length} deny rule(s) are advisory only — the wildcards readmit them`,
        });
      }
    }
  }

  // ── ANU-I-005 → path write-deny ─────────────────────────────────────────────
  for (const p of PROTECTED_SOURCES) writeDeny.push({ path: p, invariant: "ANU-I-005" });
  coverage.push({
    invariant: "ANU-I-005",
    title: "The permissive layer's own state sources are not hand-written by the agent",
    projection: "partial",
    detail:
      `${writeDeny.length} path(s) emitted as a write-deny set. This projects into a path-enforcement ` +
      `face (AppArmor or Landlock), not into egress or exec, so it binds a stranger only once that ` +
      `face carries these paths. Emitting them is not the same as enforcing them.`,
    emitted: writeDeny.length,
  });

  // ── Invariants with no coarse projection ────────────────────────────────────
  coverage.push({
    invariant: "ANU-I-002",
    title: "Target file is held by no other live session",
    projection: "none",
    detail:
      "depends on which sessions are alive and what they touched in the last thirty minutes. The kernel " +
      "sees a write to a path; it cannot see that another agent is mid-edit. No coarse form exists.",
    emitted: 0,
  });
  coverage.push({
    invariant: "ANU-I-003",
    title: "Shared git index holds nothing this session did not stage",
    projection: "none",
    detail:
      "depends on the contents of a git index at the moment of the commit. Nothing at the syscall " +
      "boundary distinguishes a scoped commit from a sweeping one.",
    emitted: 0,
  });
  coverage.push({
    invariant: "ANU-I-004",
    title: "Declared port is free, or already held by this same service",
    projection: "none",
    detail:
      "concerns binding a port, not reaching one, and depends on who currently holds it. Egress rules " +
      "govern outbound reach and cannot express it.",
    emitted: 0,
  });

  const unbound = coverage.filter(c => c.projection === "none").map(c => c.invariant);

  // @rule:ANU-010 — the digest covers what was compiled FROM, so a changed declaration
  // shows up as a changed policy rather than as a silent divergence.
  const input_digest = createHash("sha256")
    .update(
      JSON.stringify({
        domain,
        trustMask,
        loopbackPorts: (opts.loopbackPorts ?? []).slice().sort((a, b) => a - b),
        dbs: dbs.known
          ? dbs.value.map(d => [d.name, d.host, d.port, d.klass]).sort()
          : { unreadable: dbs.why },
        protected: [...PROTECTED_SOURCES].sort(),
        roots: overriddenRoots().slice().sort(),
        base: base.allow.map(e => [e.host, e.port]).sort(),
      }),
    )
    .digest("hex");

  return {
    agent_id: agentId,
    domain,
    trust_mask: trustMask,
    generated_at: new Date().toISOString(),
    input_digest,
    egress_allow: egressAllow,
    egress_deny: egressDeny,
    write_deny: writeDeny,
    coverage,
    unbound_by_coarse: unbound,
    notes,
    state_roots_overridden: overriddenRoots(),
  };
}

// ── Drift check ───────────────────────────────────────────────────────────────

export interface DriftResult {
  matches: boolean;
  differences: string[];
}

/**
 * @rule:ANU-010 — a compiled artefact's only valid assertion is that re-deriving reproduces it.
 * `generated_at` is excluded because a timestamp is not a policy.
 */
export function checkDrift(onDisk: CoarsePolicy, fresh: CoarsePolicy): DriftResult {
  const differences: string[] = [];

  if (onDisk.input_digest !== fresh.input_digest) {
    differences.push(
      `input_digest ${onDisk.input_digest.slice(0, 12)}… → ${fresh.input_digest.slice(0, 12)}… — the declarations this was compiled from have changed`,
    );
  }

  const norm = (p: CoarsePolicy) =>
    JSON.stringify({
      egress_allow: p.egress_allow.map(e => [e.host, e.port]).sort(),
      egress_deny: p.egress_deny.map(e => [e.host, e.port, e.invariant]).sort(),
      write_deny: p.write_deny.map(e => e.path).sort(),
      coverage: p.coverage.map(c => [c.invariant, c.projection, c.emitted]).sort(),
      unbound: [...p.unbound_by_coarse].sort(),
    });

  if (norm(onDisk) !== norm(fresh)) differences.push("compiled rules differ from the on-disk policy");

  return { matches: differences.length === 0, differences };
}

// ── Reporting ─────────────────────────────────────────────────────────────────

export function renderPolicy(p: CoarsePolicy): string {
  const L: string[] = [];
  L.push(`\ncoarse policy for ${p.agent_id}  (domain=${p.domain}, trust_mask=0x${p.trust_mask.toString(16)})`);
  L.push(`compiled from declarations digest ${p.input_digest.slice(0, 16)}…\n`);

  L.push(`  egress allow   ${p.egress_allow.length}`);
  L.push(`  egress deny    ${p.egress_deny.length}`);
  for (const d of p.egress_deny) L.push(`    DENY ${d.host}:${d.port}  [${d.invariant}] ${d.reason}`);
  L.push(`  write deny     ${p.write_deny.length} path(s)  [ANU-I-005]`);

  L.push(`\n  coverage — which fine invariants survive projection:`);
  for (const c of p.coverage) {
    const mark = c.projection === "projected" ? "full   " : c.projection === "partial" ? "partial" : "NONE   ";
    L.push(`    ${mark} ${c.invariant}  ${c.title}`);
    L.push(`            ${c.detail}`);
  }

  if (p.state_roots_overridden.length) {
    L.push(`\n  NOTE — compiled against non-default state roots: ${p.state_roots_overridden.join(", ")}`);
    L.push(`  Whoever chose where the instrument lives chose what it reads (ANU-007).`);
  }

  if (p.notes.length) {
    L.push(`\n  compiler notes:`);
    for (const n of p.notes) L.push(`    [${n.kind}] ${n.detail}`);
  }

  if (p.unbound_by_coarse.length) {
    L.push(
      `\n  ${p.unbound_by_coarse.length} invariant(s) have NO coarse form: ${p.unbound_by_coarse.join(", ")}`,
    );
    L.push(`  These bind an agent that calls the permissive layer. They do not bind a stranger.`);
  }
  return L.join("\n") + "\n";
}

// ── Projection into the path face (AppArmor) ─────────────────────────────────
//
// The write-deny set is not enforcement until something carries it. The
// kavachos-agent profile is already attached at every launch via `aa-exec`, and
// AppArmor resolves deny over allow, so a generated deny block inside it turns
// ANU-I-005 from an emitted list into a rule that binds a process which never
// asked to be bound.
//
// WRITE is denied; READ is not. The permissive layer has to read these files to
// do its job, and so do plenty of legitimate agents. What must not happen is the
// governed process editing the instrument that governs it.

export const APPARMOR_BEGIN = "  # >>> anumati: generated from ANU-I-005 — do not hand-edit";
export const APPARMOR_END = "  # <<< anumati";

/** The deny block, exactly as it should appear inside the profile. */
export function renderApparmorBlock(p: CoarsePolicy): string {
  // Digest of THIS block's own inputs, not the whole policy. A generated artefact must
  // change only when its own inputs change; keying it on the full policy digest made the
  // path face report drift every time an unrelated declaration moved, which trains people
  // to regenerate on a signal that meant nothing.
  const own = createHash("sha256")
    .update(JSON.stringify(p.write_deny.map(w => w.path).sort()))
    .digest("hex");
  const lines = [APPARMOR_BEGIN];
  lines.push(`  # ${p.write_deny.length} path(s) · digest ${own.slice(0, 16)}`);
  for (const w of p.write_deny.slice().sort((a, b) => a.path.localeCompare(b.path))) {
    // wkl = write, lock, link. Read is deliberately left alone.
    lines.push(`  deny ${w.path} wkl,`);
  }
  lines.push(APPARMOR_END);
  return lines.join("\n");
}

/**
 * Splice the generated block into a profile, replacing any previous one.
 * Returns null when the profile has no closing brace to insert before.
 */
export function spliceApparmorProfile(profile: string, block: string): string | null {
  const begin = profile.indexOf(APPARMOR_BEGIN);
  if (begin !== -1) {
    const end = profile.indexOf(APPARMOR_END, begin);
    if (end === -1) return null;
    return profile.slice(0, begin) + block + profile.slice(end + APPARMOR_END.length);
  }
  // First insertion — immediately before the profile's closing brace.
  const close = profile.lastIndexOf("}");
  if (close === -1) return null;
  return profile.slice(0, close) + block + "\n" + profile.slice(close);
}

/** @rule:ANU-010 — the profile's generated block must be what the invariants compile to. */
export function apparmorBlockMatches(profile: string, block: string): boolean {
  const begin = profile.indexOf(APPARMOR_BEGIN);
  if (begin === -1) return false;
  const end = profile.indexOf(APPARMOR_END, begin);
  if (end === -1) return false;
  return profile.slice(begin, end + APPARMOR_END.length) === block;
}
