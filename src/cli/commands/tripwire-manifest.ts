// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// `aegis tripwire-manifest [--external | --check-internal <file>]` — AF-T-606.
//   --external (default): print the EXTERNAL MCP manifest (the honeypot tools an outside caller
//     would see). Actually SERVING this on a public endpoint is a founder-ruled deployment step.
//   --check-internal <manifest.json>: assert an internal manifest contains NO honeypot tool
//     (the AGT-018 guard) — exits non-zero on a violation. @rule:AGT-018

import { readFileSync, existsSync } from "fs";
import { externalManifest, assertInternalManifestClean } from "../../tripwire/manifest";

export default async function tripwireManifest(args: string[]): Promise<void> {
  const ci = args.indexOf("--check-internal");
  if (ci >= 0 && args[ci + 1]) {
    const path = args[ci + 1];
    if (!existsSync(path)) { process.stderr.write(`[MANIFEST] not found: ${path}\n`); process.exit(1); }
    let tools: { name: string }[];
    try {
      const parsed = JSON.parse(readFileSync(path, "utf-8"));
      tools = Array.isArray(parsed) ? parsed : (parsed.tools ?? []);
    } catch (e: any) { process.stderr.write(`[MANIFEST] unreadable: ${e?.message}\n`); process.exit(1); }
    const r = assertInternalManifestClean(tools);
    if (r.ok) { process.stdout.write(`✓ internal manifest clean — no honeypot tool present (${tools.length} tool(s) checked)\n`); process.exit(0); }
    process.stderr.write(`✗ AGT-018 VIOLATION — honeypot tool(s) in the internal manifest: ${r.violations.join(", ")}\n`);
    process.exit(1);
  }
  // Default: print the external manifest.
  process.stdout.write(JSON.stringify({ tools: externalManifest() }, null, 2) + "\n");
  process.exit(0);
}
