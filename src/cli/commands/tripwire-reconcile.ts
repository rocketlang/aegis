// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// `aegis tripwire-reconcile` — AF-T-604. Reconciles registered principals (Claude sessions +
// mudrika-issued identities) against principals that ACTED (distinct sessions in the anumati /
// tripwire ledgers). Unregistered actors are lurker candidates, classified test vs unexplained.
// Reads only; decides nothing (an unregistered scenario run is not an intruder). @rule:AFW-010

import { readFileSync, existsSync, readdirSync } from "fs";
import { join } from "path";
import { reconcile, classifyLurkers } from "../../tripwire/reconcile";

const AEGIS_DIR = join(process.env.HOME || "/root", ".aegis");
const STATE_DIR = "/root/.ankr/state";

function registeredIds(): Set<string> {
  const out = new Set<string>();
  // Claude sessions the registry knows.
  try {
    const s = JSON.parse(readFileSync(join(STATE_DIR, "claude-sessions.json"), "utf-8")) as Record<string, unknown>;
    for (const id of Object.keys(s)) out.add(id);
  } catch { /* absent = none */ }
  // Mudrika-issued identities (one file per agent).
  try {
    for (const f of readdirSync(join(AEGIS_DIR, "agents"))) {
      if (f.endsWith(".mudrika.json")) out.add(f.replace(/\.mudrika\.json$/, ""));
    }
  } catch { /* absent = none */ }
  return out;
}

function observedActors(): Set<string> {
  const out = new Set<string>();
  for (const name of ["anumati.jsonl", "tripwire.jsonl"]) {
    const p = join(AEGIS_DIR, name);
    if (!existsSync(p)) continue;
    for (const line of readFileSync(p, "utf-8").split("\n")) {
      if (!line.trim()) continue;
      try { const s = JSON.parse(line).session; if (s) out.add(String(s)); } catch { /* skip */ }
    }
  }
  return out;
}

export default async function tripwireReconcile(_args: string[]): Promise<void> {
  const r = reconcile(registeredIds(), observedActors());
  const { likelyTest, unexplained } = classifyLurkers(r.lurkers);

  let out = "# Agent Tripwire — registry reconciliation (AF-T-604)\n\n";
  out += `Registered principals: ${r.registeredCount} (Claude sessions + mudrika identities)\n`;
  out += `Observed acting (in ledgers): ${r.observedCount} · matched to registry: ${r.matched.length}\n`;
  out += `**Unregistered actors: ${r.lurkers.length}** — ${likelyTest.length} likely test/scenario, **${unexplained.length} unexplained**\n\n`;
  if (unexplained.length) {
    out += "## Unexplained — acted but not registered, not a known test runner (look here)\n";
    for (const id of unexplained) out += `- ${id}\n`;
  } else {
    out += "✓ every unregistered actor matches a known test/scenario pattern; none unexplained.\n";
  }
  if (likelyTest.length) out += `\n(${likelyTest.length} likely-test actors omitted: e.g. ${likelyTest.slice(0, 3).join(", ")}…)\n`;
  process.stdout.write(out);
  // Report only — an unregistered scenario run is not an intruder; a human reads the unexplained list.
  process.exit(0);
}
