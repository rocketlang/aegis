// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// KAVACH — the measured launch.
//
// @rule:PRA-005 What governs an agent is measured into one value, and that value is
//               derivable from the declarations alone, before any agent runs
// @rule:PRA-006 A launch measurement is compared against a reference published once;
//               a difference is drift, and drift is reported, never reconciled
//
// WHERE THIS COMES FROM
//
// A peer's answer to the question this codebase had been stuck on: off-host
// confirmation seemed expensive because we pictured a second machine that WATCHES.
// Their boot chain showed a second machine that COMPARES — against values published once
// and checkable with nothing but those values and a public key. That is a different
// cost, and a much lower one.
//
// The same shape applies one layer up. A governed agent launch already produces the
// pieces: a seccomp profile, an exec allowlist, an egress policy, a path-deny set, and
// a compiled coarse policy. Each was computed and then forgotten locally. Extending
// them into a single value, in a fixed order, makes "what is governing this agent?"
// a question a second machine can answer.
//
// The extend is deliberately theirs: E(p, d) = sha256(p || d) from 32 zero bytes, closed
// with a separator. Not because the arithmetic is special, but because a reader who
// knows one can read the other, and because the two can be reasoned about together.
//
// HONEST CEILING — read this before describing the feature.
//
// The host computes its own measurement, so this does NOT survive a host that lies.
// It is not a TPM quote and must never be called one. What it buys is that the
// enforcement configuration becomes a PUBLISHED, offline-checkable fact instead of a
// local one: accidental drift is caught, tampering that does not bother to forge the
// measurement is caught, and if a hardware root of trust is ever added there is now a
// fixed value for it to attest. Rung three for the reference half; the quote half is
// still unattested. Say both.

import { createHash } from "crypto";
import { existsSync, readFileSync } from "fs";
import { generateSeccompProfile, canonicalJson } from "../kernel/seccomp-profile-generator";
import { buildExecAllowlist } from "../kernel/exec-allowlist";
import { compilePolicy } from "./compile-policy";
import { readHostTrust, type HostTrust } from "./host-trust";

export const LAUNCH_MEASUREMENT_FORMAT = "aegis-launch-measurement/1";

/** Components extend in this order and no other. Order is part of the value. */
export const COMPONENT_ORDER = ["seccomp", "exec_allowlist", "egress", "path_deny", "coarse"] as const;
export type ComponentName = (typeof COMPONENT_ORDER)[number];

export interface LaunchMeasurement {
  format: string;
  /** What the value is a function of — never a session id, a path, or a timestamp. */
  declarations: { trust_mask: number; domain: string; agent_type: string; strict_exec: boolean; delegation_depth: number };
  components: Record<ComponentName, string>;
  /** The chained value. This is the thing a second machine compares. */
  measurement: string;
  /** Roots this was computed against, if not the defaults (ANU-007). */
  state_roots_overridden: string[];
  /**
   * On what basis the host asserting this measurement is believed honest. @rule:PRA-007
   *
   * DELIBERATELY NOT CHAINED, and the reason matters. The reference must be derivable
   * from the declarations alone (PRA-005) so that one published file serves every host.
   * Host trust is a property of a MACHINE, not of the declarations — fold it into the
   * chain and the same declarations would measure differently on two hosts, which would
   * destroy the only property that makes an off-host comparison possible.
   *
   * So it sits beside the value and qualifies it: the measurement says WHAT governs the
   * agent, this says how much the host's word on that is worth. Present on an observed
   * measurement; absent from a reference, which has no host.
   */
  host_trust?: { level: HostTrust; why: string; claim_refused?: string };
}

const ZERO = Buffer.alloc(32);
const SEP = createHash("sha256").update(Buffer.from("ffffffff", "hex")).digest();

function extend(cur: Buffer, digest: Buffer): Buffer {
  return createHash("sha256").update(Buffer.concat([cur, digest])).digest();
}

const sha = (s: string) => createHash("sha256").update(s).digest();

export interface LaunchOptions {
  trustMask: number;
  domain: string;
  agentType?: string;
  strictExec?: boolean;
  delegationDepth?: number;
  loopbackPorts?: number[];
}

/**
 * Compute each component digest from the DECLARATIONS alone.
 *
 * Nothing here reads a launch artefact, so the reference can be published with a
 * release, before any agent has run — which is the property that makes an off-host
 * comparison possible at all. Everything session-specific is excluded by construction:
 * a measurement that varied per launch could never be compared with anything.
 */
export function measureComponents(opts: LaunchOptions): Record<ComponentName, string> {
  const agentType = opts.agentType ?? "claude-code";
  const strictExec = opts.strictExec ?? false;
  const depth = opts.delegationDepth ?? 1;

  // 1. seccomp — the syscall set, canonicalised so key order cannot change the value
  const prof = generateSeccompProfile(opts.trustMask, opts.domain, agentType, strictExec, depth);
  const syscalls = JSON.parse(canonicalJson(prof.profile)) as { syscalls?: Array<{ action: string; names: string[] }> };
  const seccompCanon = (syscalls.syscalls ?? [])
    .map(e => `${e.action}:${[...e.names].sort().join(",")}`)
    .sort()
    .join("|");

  // 2. exec allowlist — paths only; notes are commentary and must not move the value
  const execList = buildExecAllowlist(agentType, strictExec);
  const execCanon = strictExec
    ? execList.allow.map(e => e.path).sort().join("|")
    : "strict_exec=off";

  // 3+4+5. the compiled coarse policy carries egress, the path-deny set and its own digest
  const coarse = compilePolicy({
    agentId: "reference",            // never part of the value — see below
    domain: opts.domain,
    trustMask: opts.trustMask,
    loopbackPorts: opts.loopbackPorts ?? [],
  });
  const egressCanon = [
    ...coarse.egress_allow.map(e => `A:${e.host}:${e.port}`),
    ...coarse.egress_deny.map(e => `D:${e.host}:${e.port}`),
  ].sort().join("|");
  const pathDenyCanon = coarse.write_deny.map(w => w.path).sort().join("|");

  return {
    seccomp: sha(seccompCanon).toString("hex"),
    exec_allowlist: sha(execCanon).toString("hex"),
    egress: sha(egressCanon).toString("hex"),
    path_deny: sha(pathDenyCanon).toString("hex"),
    coarse: coarse.input_digest,
  };
}

/** Extend the components in COMPONENT_ORDER and close with the separator. */
export function chain(components: Record<ComponentName, string>): string {
  let v = ZERO;
  for (const name of COMPONENT_ORDER) v = extend(v, Buffer.from(components[name], "hex"));
  return extend(v, SEP).toString("hex");
}

/**
 * The reference: what a launch with these declarations SHOULD measure.
 * Publish this with a release; a second machine needs nothing else to compare.
 */
export function launchReference(opts: LaunchOptions): LaunchMeasurement {
  const { overriddenRoots } = require("./plant-state") as typeof import("./plant-state");
  const components = measureComponents(opts);
  return {
    format: LAUNCH_MEASUREMENT_FORMAT,
    declarations: {
      trust_mask: opts.trustMask,
      domain: opts.domain,
      agent_type: opts.agentType ?? "claude-code",
      strict_exec: opts.strictExec ?? false,
      delegation_depth: opts.delegationDepth ?? 1,
    },
    components,
    measurement: chain(components),
    state_roots_overridden: overriddenRoots(),
  };
}

// ── Comparison ────────────────────────────────────────────────────────────────

export interface Comparison {
  agrees: boolean;
  /** Components that differ, named. A single value tells you THAT it drifted; these tell you where. */
  differing: Array<{ component: ComponentName; reference: string; observed: string }>;
  note: string;
}

/**
 * @rule:PRA-006 — a difference is drift, reported and never reconciled. The point of
 * naming the differing component is that "the measurement changed" is unactionable
 * while "the egress policy changed" is a place to look.
 */
export function compareLaunch(reference: LaunchMeasurement, observed: LaunchMeasurement): Comparison {
  const differing: Comparison["differing"] = [];
  for (const c of COMPONENT_ORDER) {
    if (reference.components[c] !== observed.components[c]) {
      differing.push({ component: c, reference: reference.components[c], observed: observed.components[c] });
    }
  }
  const agrees = differing.length === 0 && reference.measurement === observed.measurement;

  let note: string;
  if (agrees) {
    // Agreement is worth exactly as much as the host asserting it. Naming the rung here
    // stops a green result from being read as more than it is. @rule:PRA-007
    const ht = observed.host_trust;
    note = ht
      ? `the launch measures what the published reference says it should, on the word of a host at host_trust=${ht.level}`
      : "the launch measures what the published reference says it should";
  } else if (differing.length === 0) {
    // Components all agree but the chained value does not — that is not drift in the
    // configuration, it is a defect in the chaining or a format mismatch.
    note = "components agree but the chained values differ — a compiler bug or a format mismatch, not configuration drift";
  } else {
    note = `${differing.length} component(s) differ from the published reference`;
  }
  return { agrees, differing, note };
}

export function renderLaunch(m: LaunchMeasurement): string {
  const L: string[] = [];
  L.push(`\nlaunch measurement  ${m.measurement}`);
  L.push(`  trust_mask=0x${m.declarations.trust_mask.toString(16)} domain=${m.declarations.domain} ` +
         `agent_type=${m.declarations.agent_type} strict_exec=${m.declarations.strict_exec} depth=${m.declarations.delegation_depth}`);
  L.push(`  extended in order:`);
  for (const c of COMPONENT_ORDER) L.push(`    ${c.padEnd(15)} ${m.components[c]}`);
  if (m.state_roots_overridden.length) {
    L.push(`  NOTE — non-default state roots: ${m.state_roots_overridden.join(", ")}`);
  }
  if (m.host_trust) {
    L.push(`  host_trust      ${m.host_trust.level}  (not chained — qualifies the value, is not part of it)`);
    L.push(`                  ${m.host_trust.why}`);
    if (m.host_trust.claim_refused) {
      L.push(`                  REFUSED — ${m.host_trust.claim_refused}`);
    }
  }
  L.push(`\n  The host computed this about itself. At host_trust=assumed it is not a TPM`);
  L.push(`  quote and does not survive a host that lies. What it gives a second machine`);
  L.push(`  is a published value to compare against, which is what makes the check`);
  L.push(`  possible off-host.`);
  return L.join("\n") + "\n";
}

// ── The observed side ─────────────────────────────────────────────────────────
//
// Computing the launch value from the same declarations as the reference would make
// the two trivially equal and prove nothing. The observed side therefore measures the
// ARTEFACTS THAT WERE ACTUALLY WRITTEN — the profile the kernel will load, the
// allowlist the supervisor will consult, the coarse policy the egress face was given.
// Agreement then means the files on disk say what the declarations say they should.

export interface LaunchArtefacts {
  profilePath: string;
  execAllowlistPath: string | null;   // null when strict_exec is off
  coarsePath: string;
}

export function measureLaunchFromArtefacts(
  a: LaunchArtefacts,
  decl: LaunchMeasurement["declarations"],
): LaunchMeasurement | { error: string } {
  const readJson = (p: string) => {
    if (!existsSync(p)) return { error: `missing artefact: ${p}` };
    try {
      return { value: JSON.parse(readFileSync(p, "utf-8")) };
    } catch (e: any) {
      return { error: `unreadable artefact ${p}: ${e?.message}` };
    }
  };

  const prof = readJson(a.profilePath);
  if ("error" in prof) return prof;
  const coarse = readJson(a.coarsePath);
  if ("error" in coarse) return coarse;

  const syscalls = (prof.value.syscalls ?? []) as Array<{ action: string; names: string[] }>;
  const seccompCanon = syscalls
    .map(e => `${e.action}:${[...e.names].sort().join(",")}`)
    .sort()
    .join("|");

  let execCanon = "strict_exec=off";
  if (a.execAllowlistPath) {
    const ex = readJson(a.execAllowlistPath);
    if ("error" in ex) return ex;
    execCanon = ((ex.value.allow ?? []) as Array<{ path: string }>)
      .map(e => e.path).sort().join("|");
  }

  const c = coarse.value;
  const egressCanon = [
    ...((c.egress_allow ?? []) as Array<{ host: string; port: number }>).map(e => `A:${e.host}:${e.port}`),
    ...((c.egress_deny ?? []) as Array<{ host: string; port: number }>).map(e => `D:${e.host}:${e.port}`),
  ].sort().join("|");
  const pathDenyCanon = ((c.write_deny ?? []) as Array<{ path: string }>)
    .map(w => w.path).sort().join("|");

  const components: Record<ComponentName, string> = {
    seccomp: sha(seccompCanon).toString("hex"),
    exec_allowlist: sha(execCanon).toString("hex"),
    egress: sha(egressCanon).toString("hex"),
    path_deny: sha(pathDenyCanon).toString("hex"),
    coarse: String(c.input_digest ?? ""),
  };

  // The observed side has a host; the reference does not. Read the rung here and nowhere
  // else, so a published reference stays byte-identical no matter who built it.
  const ht = readHostTrust();

  return {
    format: LAUNCH_MEASUREMENT_FORMAT,
    declarations: decl,
    components,
    measurement: chain(components),
    state_roots_overridden: (c.state_roots_overridden ?? []) as string[],
    host_trust: {
      level: ht.level,
      why: ht.why,
      ...(ht.claim_refused ? { claim_refused: ht.claim_refused } : {}),
    },
  };
}
