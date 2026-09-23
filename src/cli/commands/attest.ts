// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// aegis attest reference [--trust-mask N] [--domain D] [--strict-exec] [--needs=P,P]
//     what a launch with these declarations SHOULD measure. Publish it with a release.
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
      console.log(`\n  The host computed the observed value about itself — this is not a TPM`);
      console.log(`  quote and does not survive a host that lies.`);
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

  console.error("usage: aegis attest <reference|verify> ...");
  process.exit(1);
}
