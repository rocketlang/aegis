// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// aegis anumati            — what the permissive layer refused (or would have)
// aegis anumati mode       — current mode
// aegis anumati mode enforce|shadow
// aegis anumati try <tool> <command|path>  — evaluate one action without running it
//
// @rule:ANU-YK-001 A silent shadow is a guard that has already decayed. This is the surface
//                  that makes shadow visible, because a PreToolUse hook exiting 0 may have
//                  its stderr swallowed by the harness.

import { existsSync, readFileSync, writeFileSync, mkdirSync } from "fs";
import { anumati, anumatiMode, renderRefusal, type ProposedAction } from "../../kavach/anumati";

const LEDGER = "/root/.aegis/anumati.jsonl";
const MODE_FILE = "/root/.aegis/anumati-mode";

export default async function anumatiCmd(args: string[]): Promise<void> {
  const sub = args[0];

  if (sub === "mode") {
    const want = args[1];
    if (!want) {
      console.log(`anumati mode: ${anumatiMode()}`);
      return;
    }
    if (want !== "shadow" && want !== "enforce") {
      console.error("usage: aegis anumati mode [shadow|enforce]");
      process.exit(1);
    }
    mkdirSync("/root/.aegis", { recursive: true });
    writeFileSync(MODE_FILE, `${want}\n`);
    console.log(`anumati mode → ${want}`);
    if (want === "enforce") {
      console.log("Refusals now bite. Authority is untouched (ANU-005) — resolve plant state and ask again.");
    }
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
