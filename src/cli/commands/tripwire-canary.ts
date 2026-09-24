// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// `aegis tripwire-canary mint --label <x> --placement <where>` — mint a document canary, add
// it to the registry (so a later trip is attributable), and print the bait line to embed.
// `aegis tripwire-canary list` — show registered canaries. AF-T-603. @rule:AGT-018

import { readFileSync, writeFileSync, existsSync, mkdirSync } from "fs";
import { join } from "path";
import { mintCanary, type Canary } from "../../tripwire/canary";

const AEGIS_DIR = join(process.env.HOME || "/root", ".aegis");
const REGISTRY = join(AEGIS_DIR, "tripwire-canaries.json");

export function loadCanaries(): Canary[] {
  try { return existsSync(REGISTRY) ? (JSON.parse(readFileSync(REGISTRY, "utf-8")) as Canary[]) : []; }
  catch { return []; }
}

function flag(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  return i >= 0 && args[i + 1] ? args[i + 1] : undefined;
}

export default async function tripwireCanary(args: string[]): Promise<void> {
  const sub = args[0];
  if (sub === "list") {
    const cs = loadCanaries();
    process.stdout.write(cs.length ? cs.map((c) => `${c.token}  ${c.label}  @ ${c.placement}  (${c.minted})`).join("\n") + "\n" : "no canaries registered\n");
    process.exit(0);
  }
  if (sub === "mint") {
    const label = flag(args, "--label") ?? "unlabelled";
    const placement = flag(args, "--placement") ?? "unspecified";
    const canary = mintCanary({ label, placement });
    const all = [...loadCanaries(), canary];
    try {
      mkdirSync(AEGIS_DIR, { recursive: true });
      writeFileSync(REGISTRY, JSON.stringify(all, null, 2));
    } catch (e: any) {
      process.stderr.write(`[CANARY] could not write registry: ${e?.message}\n`);
      process.exit(1);
    }
    process.stdout.write(`# canary minted: ${canary.token} (${label} @ ${placement})\n# embed this line in the document:\n\n${canary.text}\n`);
    process.exit(0);
  }
  process.stderr.write("usage: aegis tripwire-canary mint --label <x> --placement <where> | list\n");
  process.exit(1);
}
