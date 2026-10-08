// SPDX-License-Identifier: AGPL-3.0-only
// aegis red-team — ATTESTATION: identify a malformed / impostor agent (2026-10-08).
//
// Proves the boundary check refuses the three ways an agent can be "not what you authorized": wrong
// code/config (measurement != pinned baseline), wrong identity (not signed by the registered key),
// and no baseline (unknown is refused, never trusted). An intact, correctly-signed agent passes.
// Drives the real measurer + verifier; hermetic (crypto + temp files, no root).
//
// Honest note printed at the end: this proves the CHECK. Its guarantee is only as strong as who took
// the measurement — self-measurement can lie; the launcher must measure, and hardware attestation is
// the ceiling. Runs against repo source: src/core/attest.ts.
import { generateIdentityKeypair, measureFiles, signMeasurement, verifyAttestation } from "../src/core/attest.js";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

let gaps = 0;
const SAFE = (id: string, ok: boolean, detail: string) => { console.log(`  [${ok ? "safe" : "GAP "}] ${id} — ${detail}`); if (!ok) gaps++; };

const dir = mkdtempSync(join(tmpdir(), "attest-"));
const files = ["agent.js", "config.json", "policy.yaml"].map((f) => join(dir, f));
writeFileSync(files[0], "export const run = () => 'good agent';\n");
writeFileSync(files[1], '{"scope":"read-only"}\n');
writeFileSync(files[2], "rules: [allow-read]\n");

const id = generateIdentityKeypair();
const baseline = measureFiles(files, dir).digest;              // the operator pins this for the approved build
const good = measureFiles(files, dir).digest;                  // the launcher re-measures at the boundary
const goodSig = signMeasurement(good, id.privateKey);

// 1) control — intact code + correct identity → attested
SAFE("an intact, correctly-signed agent attests", verifyAttestation(good, goodSig, id.publicKey, baseline).ok === true,
  "measurement == baseline, signed by the registered key → OK");

// 2) tampered code — flip a byte in config → digest changes → refused
writeFileSync(files[1], '{"scope":"admin"}\n');                 // privilege-escalated config
const tampered = measureFiles(files, dir).digest;
const vT = verifyAttestation(tampered, signMeasurement(tampered, id.privateKey), id.publicKey, baseline);
SAFE("tampered code/config is refused", vT.ok === false && vT.kind === "measurement",
  `change config scope → digest differs from baseline → ${vT.ok ? "OK(!)" : vT.kind}`);
writeFileSync(files[1], '{"scope":"read-only"}\n');             // restore

// 3) impostor — a different identity key signs the (correct) measurement → refused
const other = generateIdentityKeypair();
const vI = verifyAttestation(good, signMeasurement(good, other.privateKey), id.publicKey, baseline);
SAFE("an impostor identity is refused", vI.ok === false && vI.kind === "identity",
  `right code, but signed by a non-registered key → ${vI.ok ? "OK(!)" : vI.kind}`);

// 4) no baseline — unknown is refused, never trusted
const vN = verifyAttestation(good, goodSig, id.publicKey, null);
SAFE("no pinned baseline is refused, not trusted", vN.ok === false && vN.kind === "no-baseline",
  `an agent with no pinned baseline → ${vN.ok ? "OK(!)" : vN.kind}`);

rmSync(dir, { recursive: true, force: true });
console.log(`\n  attestation: ${gaps} gap(s)` + (gaps === 0 ? " — tampered / impostor / unpinned all refused ✓ (CHECK only; the measurer must be the launcher, hardware-root is the ceiling)" : " (RED until fixed)"));
process.exit(gaps > 0 ? 1 : 0);
