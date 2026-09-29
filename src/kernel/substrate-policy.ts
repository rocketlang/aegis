// SPDX-License-Identifier: AGPL-3.0-only
//
// substrate-policy — compile an agent's egress allowlist FROM the declaration, and
// report drift between what was declared and what is enforced.
//
// WHY THIS EXISTS
//
// The weakest link in the runtime-attestation story was never the cryptography. A
// receipt can carry a digest of the enforced policy, and that digest can be published
// and compared — but it says nothing about where the policy came from. A hand-authored
// allowlist, copied from device to device and edited under pressure, is attested
// faithfully and is still whatever somebody typed.
//
// ANKR already has the answer and it is not a new mechanism: the tree is the only
// capability truth, and every mask is a compiled view of it (FP-014). A service declares
// its dependencies in its codex. So the set of places an agent for that service may
// reach is not a matter of opinion — it is `depends_on`, resolved through the port
// authority, and nothing else.
//
// That turns the allowlist from an artefact somebody maintains into a COMPILED VIEW.
// Drift between the declaration and the running policy stops being a configuration
// question and becomes what FP-016 already calls it: a compiler bug.
//
// WHAT THIS DOES NOT DO
//
// Egress only. "What may reach this agent" is a different question with a different
// answer: ingress is an authorisation decision (Forja TRUST, the permissive layer), not
// a cgroup hook, because by the time a connection arrives the caller's identity matters
// and an IP does not establish it. Both compile from the same tree; only one of them
// compiles to a BPF map. Saying so here because "bind the agent to the substrate"
// naturally reads as covering both, and it does — through two different enforcers.
//
// Pure: no filesystem, no network, no config loading. The caller supplies the codex and
// the resolver, so this is testable without the machine it describes.

/** The parts of a codex.json this compiler reads. Deliberately few. */
export interface CodexLike {
  service: string;
  depends_on?: string[];
  /** Endpoints outside the fleet that the service declares it must reach. Each must
   *  carry a reason: an undocumented hole is how an allowlist rots. */
  external_egress?: Array<{ host: string; port: number; why: string }>;
}

export interface AllowEntry {
  host: string;
  port: number;
  /** Why this entry exists, carried through to the policy file so a reader of the
   *  DEVICE can see the justification without holding the codex. */
  note: string;
  /** "depends_on" or "external_egress" — which part of the declaration produced it. */
  source: "depends_on" | "external_egress";
}

export interface CompileResult {
  service: string;
  allow: AllowEntry[];
  /** Declared dependencies the resolver could not place. NOT silently dropped: an
   *  unresolvable dependency means the agent will be denied something it declared it
   *  needs, and the operator must see that before the device does. */
  unresolved: Array<{ name: string; reason: string }>;
}

/** Resolves a service name to where it actually listens. Supplied by the caller so this
 *  module never reads the port authority itself. */
export type Resolver = (serviceName: string) => { host: string; port: number } | null;

/**
 * The allowlist IS the declaration. Nothing is added that the codex does not claim.
 */
export function compileEgress(codex: CodexLike, resolve: Resolver): CompileResult {
  const allow: AllowEntry[] = [];
  const unresolved: CompileResult["unresolved"] = [];
  const seen = new Set<string>();

  for (const dep of codex.depends_on ?? []) {
    const at = resolve(dep);
    if (!at) {
      unresolved.push({ name: dep, reason: "declared in depends_on but the resolver could not place it" });
      continue;
    }
    const key = `${at.host}:${at.port}`;
    if (seen.has(key)) continue;
    seen.add(key);
    allow.push({ host: at.host, port: at.port, note: `depends_on ${dep}`, source: "depends_on" });
  }

  for (const e of codex.external_egress ?? []) {
    if (!e.why || !e.why.trim()) {
      // An external hole with no stated reason is refused at compile time rather than
      // shipped. The reason is the only thing that lets a later reader judge whether it
      // is still needed, and "it was already there" is how allowlists grow forever.
      unresolved.push({ name: `${e.host}:${e.port}`, reason: "external_egress entry has no stated reason — refused" });
      continue;
    }
    const key = `${e.host}:${e.port}`;
    if (seen.has(key)) continue;
    seen.add(key);
    allow.push({ host: e.host, port: e.port, note: `external: ${e.why}`, source: "external_egress" });
  }

  return { service: codex.service, allow, unresolved };
}

export interface Drift {
  /** Enforced on the device, absent from the declaration. The dangerous direction: the
   *  agent can reach somewhere nobody declared, and the codex would not show it. */
  undeclared: Array<{ host: string; port: number }>;
  /** Declared but not enforced. Less dangerous and still wrong — the agent will be
   *  denied something the tree says it needs, which reads as a broken service. */
  unenforced: Array<{ host: string; port: number; note: string }>;
}

/**
 * Compare a compiled allowlist against what a device is actually enforcing.
 *
 * Both directions are reported and neither is dismissed. FP-016 calls a mismatch
 * between a declaration and its compiled view a compiler bug, not a configuration
 * question, and this is the check that makes that claim falsifiable.
 */
export function driftAgainst(compiled: AllowEntry[], enforced: Array<{ host: string; port: number }>): Drift {
  const key = (h: string, p: number) => `${h}:${p}`;
  const declared = new Map(compiled.map(e => [key(e.host, e.port), e]));
  const running = new Set(enforced.map(e => key(e.host, e.port)));

  return {
    undeclared: enforced.filter(e => !declared.has(key(e.host, e.port))).map(e => ({ host: e.host, port: e.port })),
    unenforced: compiled.filter(e => !running.has(key(e.host, e.port)))
                        .map(e => ({ host: e.host, port: e.port, note: e.note })),
  };
}

/** True when the compiled view and the running policy agree exactly. */
export function inAgreement(d: Drift): boolean {
  return d.undeclared.length === 0 && d.unenforced.length === 0;
}

/**
 * The value a manifest publishes for the POLICY half (§3.1 needs tag + policy digest).
 *
 * Order-independent by construction: the same allowlist authored in a different order
 * must produce the same digest, or a reference value would depend on how a file happened
 * to be written. The note is INCLUDED — two allowlists permitting the same endpoints for
 * different stated reasons are not the same policy, and a reader comparing digests
 * should be told when the justification changed.
 */
export function policyDigest(allow: AllowEntry[], sha256: (s: string) => string): string {
  const lines = allow
    .map(e => `${e.host}\u0000${e.port}\u0000${e.source}\u0000${e.note}`)
    .sort();
  return sha256(lines.join("\n"));
}
