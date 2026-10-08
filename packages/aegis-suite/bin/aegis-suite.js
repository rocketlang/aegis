#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// aegis-suite — the one-shot front door for the xShield posture suite. `npm i @xshieldai/aegis-suite`
// pulls the whole suite (the dependency list); this CLI provisions it and points you at the control
// center. Each package stays STANDALONE and usable on its own — the suite is a convenience bundle,
// never a runtime coupling (FP-001 / standalone-first).
//
//   aegis-suite status        what's installed, which versions, whether provisioned   (default)
//   aegis-suite init          provision authority keys + print the next step
//   aegis-suite control-center  where the cockpit is, and how to start it

import { createRequire } from "module";
import { generateKeyPairSync } from "crypto";
import { existsSync, mkdirSync, writeFileSync } from "fs";
import { homedir } from "os";
import { join } from "path";

const require = createRequire(import.meta.url);
const AEGIS_DIR = process.env.AEGIS_HOME || join(homedir(), ".aegis");
const CONTROL_CENTER = `http://localhost:${process.env.AEGIS_PORT || "4850"}/control-center`;

// The bundled posture primitives (the convenience bundle). Services (varuna, nallasetu) and the n8n
// nodes install separately on purpose — they are deployments, not libraries.
const BUNDLED = [
  "@xshieldai/aegis", "@xshieldai/agent-kernel", "@xshieldai/aegis-guard",
  "@xshieldai/chitta-detect", "@xshieldai/lakshmanrekha", "@xshieldai/hanumang-mandate",
];

function installedVersion(pkg) {
  try { return require(`${pkg}/package.json`).version; } catch { return null; }
}

function status() {
  console.log("xShield suite — inventory\n");
  let missing = 0;
  for (const p of BUNDLED) {
    const v = installedVersion(p);
    if (v) console.log(`  ✓ ${p.padEnd(32)} ${v}`);
    else { console.log(`  ✗ ${p.padEnd(32)} not installed`); missing++; }
  }
  const keys = ["ledger-signing.pub", "attest-identity.pub"].map((f) => existsSync(join(AEGIS_DIR, f)));
  console.log(`\n  authority keys: ledger=${keys[0] ? "provisioned" : "absent"}  attest=${keys[1] ? "provisioned" : "absent"}`);
  console.log(`  control center: ${CONTROL_CENTER}`);
  if (missing) console.log(`\n  ${missing} package(s) missing — reinstall the suite: npm i @xshieldai/aegis-suite`);
  else if (!keys[0] || !keys[1]) console.log(`\n  run 'aegis-suite init' to provision the authority keys.`);
}

function genKeypair(name) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  writeFileSync(join(AEGIS_DIR, `${name}.key`), privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  writeFileSync(join(AEGIS_DIR, `${name}.pub`), publicKey.export({ type: "spki", format: "pem" }), { mode: 0o644 });
}

function init() {
  mkdirSync(AEGIS_DIR, { recursive: true });
  for (const name of ["ledger-signing", "attest-identity"]) {
    if (existsSync(join(AEGIS_DIR, `${name}.pub`))) { console.log(`  = ${name} already provisioned`); continue; }
    genKeypair(name);
    console.log(`  + ${name} keypair written to ${AEGIS_DIR}`);
  }
  console.log(
    "\n  Provisioned. The authority keys sign the refusal ledger (aegis ledger-verify) and attest agent\n" +
    "  identity (aegis attest). In a real deployment move the PRIVATE keys off the agent's uid (a\n" +
    "  separate account or box) — a single-box dev start keeps them here, mode 600.\n" +
    `\n  Next: start the control center and open it —\n    aegis-dashboard   # then open ${CONTROL_CENTER}\n`,
  );
}

function controlCenter() {
  console.log(`control center: ${CONTROL_CENTER}\nstart it with:  aegis-dashboard\n(it renders every primitive's events — refusals, gate decisions, ledger integrity, witness alarms — in one cockpit)`);
}

const cmd = process.argv[2] || "status";
if (cmd === "status" || cmd === "inventory") status();
else if (cmd === "init") init();
else if (cmd === "control-center" || cmd === "cc") controlCenter();
else { console.error(`unknown command '${cmd}'. Use: status | init | control-center`); process.exit(2); }
