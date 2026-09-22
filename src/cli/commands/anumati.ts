// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// aegis anumati            — what the permissive layer refused (or would have)
// aegis anumati mode       — current mode
// aegis anumati mode enforce|shadow
// aegis anumati try <tool> <command|path>  — evaluate one action without running it
// aegis anumati taint     — integrity of the layer's own state sources (ANU-007)
// aegis anumati clear <path> --reason "..."  — human release of a tainted source
// aegis anumati compile [--check] [--agent id] [--domain d] [--trust-mask n]
//     — compile the fine invariants into coarse kernel policy (ANU-008/009/010)
//
// @rule:ANU-YK-001 A silent shadow is a guard that has already decayed. This is the surface
//                  that makes shadow visible, because a PreToolUse hook exiting 0 may have
//                  its stderr swallowed by the harness.

import { existsSync, readFileSync, writeFileSync, mkdirSync } from "fs";
import { join } from "path";
import { createHash } from "crypto";
import { anumati, anumatiMode, anumatiModeStatus, renderRefusal, type ProposedAction } from "../../kavach/anumati";
import {
  readTaintedSources,
  clearTaint,
  PROTECTED_SOURCES,
  ANUMATI_MODE_FILE,
  ANUMATI_SEAL_FILE,
} from "../../kavach/plant-state";

const LEDGER = "/root/.aegis/anumati.jsonl";
const OUT_DIR = "/root/.aegis/kernel";

export default async function anumatiCmd(args: string[]): Promise<void> {
  const sub = args[0];

  if (sub === "mode") {
    const want = args[1];
    if (!want) {
      const st = anumatiModeStatus();
      console.log(`anumati mode: ${st.mode}${st.sealed ? " (sealed)" : ""}`);
      if (st.note) console.log(`  ${st.note}`);
      return;
    }
    if (want !== "shadow" && want !== "enforce") {
      console.error("usage: aegis anumati mode [shadow|enforce]");
      process.exit(1);
    }
    // @rule:ANU-007 — write the value AND a seal over it. One write can no longer
    // silently downgrade enforcement; a mismatch resolves to the stricter mode.
    mkdirSync("/root/.aegis", { recursive: true });
    const body = `${want}\n`;
    writeFileSync(ANUMATI_MODE_FILE, body);
    writeFileSync(
      ANUMATI_SEAL_FILE,
      JSON.stringify(
        { mode: want, sha256: createHash("sha256").update(body).digest("hex"), set_at: new Date().toISOString() },
        null,
        2,
      ),
    );
    console.log(`anumati mode → ${want} (sealed)`);
    if (want === "enforce") {
      console.log("Refusals now bite. Authority is untouched (ANU-005) — resolve plant state and ask again.");
    }
    return;
  }

  if (sub === "taint") {
    const t = readTaintedSources();
    if (!t.known) {
      console.error(`cannot establish source integrity: ${t.why}`);
      process.exit(2);
    }
    console.log(`protected sources (${PROTECTED_SOURCES.length}):`);
    for (const p of PROTECTED_SOURCES) {
      const hit = t.value.find(x => x.path === p);
      console.log(`  ${hit ? "TAINTED " : "clean   "} ${p}`);
      if (hit) console.log(`            ${hit.detail} — ${hit.detected_at}`);
    }
    if (t.value.length > 0) {
      console.log(`\n${t.value.length} tainted. Every permissive reading one of these now refuses.`);
      console.log(`Clear only after establishing what wrote it:`);
      console.log(`  aegis anumati clear <path> --reason "..."`);
    }
    return;
  }

  if (sub === "clear") {
    const path = args[1];
    const ri = args.indexOf("--reason");
    const reason = ri > -1 ? args.slice(ri + 1).join(" ") : "";
    if (!path || !reason) {
      console.error('usage: aegis anumati clear <path> --reason "why this source can be trusted again"');
      process.exit(1);
    }
    // Mirrors `quarantine release` — a human, with a reason, on the record.
    if (!clearTaint(path, reason)) {
      console.error(`no taint recorded against ${path}`);
      process.exit(1);
    }
    console.log(`cleared: ${path}`);
    console.log(`reason:  ${reason}`);
    return;
  }

  if (sub === "compile") {
    const { compilePolicy, checkDrift, renderPolicy } = await import("../../kavach/compile-policy");
    const { readDeclaredPort } = await import("../../kavach/plant-state");

    const flag = (name: string, fallback: string) => {
      const i = args.indexOf(`--${name}`);
      return i > -1 && args[i + 1] ? args[i + 1] : fallback;
    };
    const agentId = flag("agent", "default");
    const domain = flag("domain", "general");
    const trustMask = parseInt(flag("trust-mask", "255"), 10);

    // Loopback ports this agent legitimately needs, so the compiler can narrow the
    // any-port loopback allow instead of leaving every local deny decorative.
    const loopbackPorts: number[] = [];
    for (const svc of (flag("needs", "") || "").split(",").map(s => s.trim()).filter(Boolean)) {
      const p = readDeclaredPort(svc);
      if (p.known) loopbackPorts.push(p.value);
      else console.error(`  [warn] --needs ${svc}: ${p.why}`);
    }

    const fresh = compilePolicy({ agentId, domain, trustMask, loopbackPorts });
    const outPath = join(OUT_DIR, `${agentId}.coarse.json`);

    if (args.includes("--check")) {
      // @rule:ANU-010 — the only assertion worth making about a compiled file is that
      // re-deriving reproduces it. Anything else is drift, and drift is a compiler bug.
      if (!existsSync(outPath)) {
        console.error(`no compiled policy at ${outPath} — run \`aegis anumati compile\` first`);
        process.exit(2);
      }
      let onDisk;
      try {
        onDisk = JSON.parse(readFileSync(outPath, "utf-8"));
      } catch (e: any) {
        console.error(`compiled policy unreadable: ${e?.message}`);
        process.exit(2);
      }
      const d = checkDrift(onDisk, fresh);
      if (d.matches) {
        console.log(`compiled policy reproduces exactly (${outPath})`);
        return;
      }
      console.error(`DRIFT — the on-disk coarse policy is not what the invariants compile to:`);
      for (const diff of d.differences) console.error(`  ${diff}`);
      console.error(`\nThis is a compiler bug or a hand edit. Recompile, do not patch the output.`);
      process.exit(2);
    }

    mkdirSync(OUT_DIR, { recursive: true });
    writeFileSync(outPath, JSON.stringify(fresh, null, 2));
    process.stdout.write(renderPolicy(fresh));
    console.log(`  written: ${outPath}`);
    return;
  }

  if (sub === "enforce-paths") {
    // Project ANU-I-005 into the path face that is ALREADY attached at every launch.
    // Emitting a write-deny list is not enforcement; this is the step that makes it one.
    const { compilePolicy, renderApparmorBlock, spliceApparmorProfile, apparmorBlockMatches } =
      await import("../../kavach/compile-policy");

    const PROFILE = "/root/aegis/src/kernel/apparmor/kavachos-agent.profile";
    const policy = compilePolicy({ agentId: "path-face", domain: "general", trustMask: 255 });
    const block = renderApparmorBlock(policy);

    if (!existsSync(PROFILE)) {
      console.error(`profile not found: ${PROFILE}`);
      process.exit(2);
    }
    const current = readFileSync(PROFILE, "utf-8");

    if (args.includes("--check")) {
      // @rule:ANU-010 — a generated block's only valid assertion is that it re-derives.
      if (apparmorBlockMatches(current, block)) {
        console.log(`path face matches what ANU-I-005 compiles to (${policy.write_deny.length} path(s))`);
        return;
      }
      console.error(`DRIFT — the profile's generated block is not what the invariants compile to.`);
      console.error(`Run \`aegis anumati enforce-paths --apply\` to regenerate it.`);
      process.exit(2);
    }

    if (!args.includes("--apply")) {
      console.log(block);
      console.log(`\n# ${policy.write_deny.length} path(s). Write is denied; read is not — the layer`);
      console.log(`# must still read these, and so must legitimate agents. What must not happen`);
      console.log(`# is the governed process editing the instrument that governs it.`);
      console.log(`#\n# --apply to splice into ${PROFILE}, then reload with apparmor_parser -r`);
      return;
    }

    const next = spliceApparmorProfile(current, block);
    if (next === null) {
      console.error(`could not splice: the profile has no closing brace or an unterminated block`);
      process.exit(2);
    }
    if (next === current) {
      console.log(`path face already current (${policy.write_deny.length} path(s))`);
      return;
    }
    writeFileSync(PROFILE, next);
    console.log(`spliced ${policy.write_deny.length} deny rule(s) into ${PROFILE}`);
    console.log(`reload with:  apparmor_parser -r ${PROFILE}`);
    console.log(`(apparmor_parser validates before replacing, so a bad profile leaves the old one loaded)`);
    return;
  }

  if (sub === "try") {
    const tool = args[1];
    const rest = args.slice(2).join(" ");
    if (!tool || !rest) {
      console.error('usage: aegis anumati try <Bash|Write|Edit> "<command or path>"');
      process.exit(1);
    }
    const action: ProposedAction = {
      tool,
      session_id: process.env.CLAUDE_SESSION_ID || "cli-probe",
      cwd: process.cwd(),
      command: tool === "Bash" ? rest : undefined,
      file_path: tool === "Bash" ? undefined : rest,
    };
    const d = anumati(action);
    if (d.verdict === "PERMIT") {
      const n = d.results.length;
      console.log(`[ANUMATI] PERMIT — ${n} permissive(s) applied and all held${n === 0 ? " (none applied)" : ""}`);
      for (const r of d.results) console.log(`  ✓ ${r.id} ${r.detail}`);
      return;
    }
    process.stdout.write(renderRefusal(d, anumatiMode()));
    return;
  }

  // Default: the ledger.
  if (!existsSync(LEDGER)) {
    console.log(`anumati mode: ${anumatiMode()} — no refusals ledgered yet (${LEDGER})`);
    return;
  }

  const limit = Number(args[0]) > 0 ? Number(args[0]) : 20;
  const rows = readFileSync(LEDGER, "utf-8").trim().split("\n").filter(Boolean).slice(-limit);

  console.log(`anumati mode: ${anumatiMode()} — last ${rows.length} refusal(s)\n`);
  for (const line of rows) {
    try {
      const e = JSON.parse(line);
      const badge = e.enforced ? "BLOCKED" : "would-have";
      console.log(`${e.ts}  ${badge.padEnd(10)} ${e.tool}  ${String(e.target ?? "").slice(0, 70)}`);
      for (const r of e.refusals ?? []) console.log(`    ${r.id} ${r.verdict}: ${r.detail}`);
    } catch {
      /* skip a torn line */
    }
  }
}
