// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// aegis attest reference [--trust-mask N] [--domain D] [--strict-exec] [--needs=P,P]
//     what a launch with these declarations SHOULD measure. Publish it with a release.
//
// aegis attest host [--json]
//     on what basis THIS host is believed honest, and what was actually checked
//
// aegis attest verify --launch <session-id> [same declaration flags]
//     compare a launch against the reference. A difference is drift, named by component.
//
// @rule:PRA-005 the reference is derivable from declarations alone, before any agent runs
// @rule:PRA-006 a difference is reported, never reconciled

import { existsSync, readFileSync, writeFileSync, mkdirSync } from "fs";
import { join } from "path";
import {
  launchReference,
  compareLaunch,
  renderLaunch,
  type LaunchMeasurement,
} from "../../kavach/measure-launch";
import { AEGIS_DIR_PATH, readDeclaredPort } from "../../kavach/plant-state";
import { readHostTrust, renderHostTrust } from "../../kavach/host-trust";

const KERNEL_DIR = `${AEGIS_DIR_PATH}/kernel`;

function declFlags(args: string[]) {
  const flag = (n: string, d: string) => {
    const i = args.indexOf(`--${n}`);
    return i > -1 && args[i + 1] && !args[i + 1].startsWith("--") ? args[i + 1] : d;
  };
  const eq = (n: string) => args.find(a => a.startsWith(`--${n}=`))?.split("=")[1];

  const loopbackPorts: number[] = [];
  for (const svc of (eq("needs") ?? "").split(",").map(s => s.trim()).filter(Boolean)) {
    const p = readDeclaredPort(svc);
    if (p.known) loopbackPorts.push(p.value);
    else console.error(`  [warn] --needs ${svc}: ${p.why}`);
  }
  return {
    trustMask: parseInt(eq("trust-mask") ?? flag("trust-mask", "255"), 10),
    domain: eq("domain") ?? flag("domain", "general"),
    agentType: eq("agent-type") ?? flag("agent-type", "claude-code"),
    strictExec: args.includes("--strict-exec"),
    delegationDepth: parseInt(eq("depth") ?? flag("depth", "1"), 10),
    loopbackPorts,
  };
}

export default async function attestCmd(args: string[]): Promise<void> {
  const sub = args[0];

  // aegis attest host — on what basis is THIS host believed honest, and what was checked
  if (sub === "host") {
    const r = readHostTrust();
    if (args.includes("--json")) {
      console.log(JSON.stringify(r, null, 2));
      // A refused claim is a non-zero exit even in --json: a host that overstated itself
      // must not read as success to a script that only checks the status code.
      if (r.claim_refused) process.exit(2);
      return;
    }
    console.log("");
    console.log(renderHostTrust(r));
    if (r.claim_refused) {
      console.error(`\n  This host claimed more than its evidence supports. Nothing downstream`);
      console.error(`  should treat its measurements as more than host_trust=${r.level}.`);
      process.exit(2);
    }
    if (r.level === "assumed") {
      console.log(`\n  This is the floor and it is not a failure: it is the honest value on a`);
      console.log(`  host with no measured boot to observe. To raise it, place a declaration`);
      console.log(`  at ${AEGIS_DIR_PATH}/host-trust.json pointing at a published`);
      console.log(`  boot reference — the rung then reads up only if the PCRs actually agree.`);
    }
    return;
  }

  if (sub === "reference") {
    const ref = launchReference(declFlags(args));
    // --json emits JSON and NOTHING else. Prose on the same stream makes the flag
    // useless to the only thing that would ask for it.
    if (args.includes("--json")) {
      console.log(JSON.stringify(ref, null, 2));
      return;
    }
    process.stdout.write(renderLaunch(ref));
    const out = join(KERNEL_DIR, `reference-${ref.declarations.domain}-${ref.declarations.trust_mask}.launch.json`);
    mkdirSync(KERNEL_DIR, { recursive: true });
    writeFileSync(out, JSON.stringify(ref, null, 2));
    console.log(`  written: ${out}`);
    console.log(`  publish this with the release — a second machine needs nothing else to compare.`);
    return;
  }

  if (sub === "verify") {
    const i = args.indexOf("--launch");
    const session = i > -1 ? args[i + 1] : undefined;
    if (!session) {
      console.error("usage: aegis attest verify --launch <session-id> [--trust-mask N] [--domain D] [--strict-exec]");
      process.exit(1);
    }
    const path = session.includes("/") ? session : join(KERNEL_DIR, `${session}.launch.json`);
    if (!existsSync(path)) {
      console.error(`no launch measurement at ${path}`);
      process.exit(2);
    }
    let observed: LaunchMeasurement;
    try {
      observed = JSON.parse(readFileSync(path, "utf-8"));
    } catch (e: any) {
      console.error(`launch measurement unreadable: ${e?.message}`);
      process.exit(2);
    }

    // Declarations come from the observed record unless the caller overrides them.
    // A verifier that took the declarations from the thing being checked would be
    // letting the subject choose the question, so the flags win where given.
    const given = declFlags(args);
    const decl = {
      trustMask: args.some(a => a.startsWith("--trust-mask")) ? given.trustMask : observed.declarations.trust_mask,
      domain: args.some(a => a.startsWith("--domain")) ? given.domain : observed.declarations.domain,
      agentType: observed.declarations.agent_type,
      strictExec: args.includes("--strict-exec") || observed.declarations.strict_exec,
      delegationDepth: observed.declarations.delegation_depth,
      loopbackPorts: given.loopbackPorts,
    };

    const ref = launchReference(decl);
    const cmp = compareLaunch(ref, observed);

    console.log(`\n  reference  ${ref.measurement}`);
    console.log(`  observed   ${observed.measurement}`);
    console.log(`\n  ${cmp.note}`);
    if (cmp.agrees) {
      if (observed.state_roots_overridden.length) {
        console.log(`  NOTE — measured against non-default roots: ${observed.state_roots_overridden.join(", ")}`);
      }
      const ht = observed.host_trust;
      if (ht) {
        console.log(`\n  host_trust  ${ht.level} — ${ht.why}`);
        if (ht.claim_refused) console.error(`  REFUSED — ${ht.claim_refused}`);
      }
      if (!ht || ht.level === "assumed") {
        console.log(`\n  The host computed the observed value about itself — at this rung it is`);
        console.log(`  not a TPM quote and does not survive a host that lies.`);
      }
      return;
    }
    for (const d of cmp.differing) {
      console.error(`    ${d.component}`);
      console.error(`      reference ${d.reference}`);
      console.error(`      observed  ${d.observed}`);
    }
    console.error(`\n  Drift is reported, not reconciled: find what changed the configuration.`);
    process.exit(2);
  }

  console.error("usage: aegis attest <reference|verify|host> ...");
  process.exit(1);
}
