#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// The release gate's CI side (RPB-008, RPB-009). Run in a release workflow before publishing:
//
//   node scripts/repeat-back-check.mjs --package-dir <dir> [--pub .github/repeat-back.pub.pem] [--mode observe|enforce]
//
// It reads the annotated tag that triggered the run, checks the Repeat-back approval inside it
// against the public key pinned in this repo, and refuses unless the approval names this commit,
// this package and this version. Zero dependencies: node:crypto, node:fs, git.
//
// observe (the default until a person promotes it): a refusal is a warning, the run goes on.
// enforce: a refusal stops the run (exit 1). A manual run with no tag is a rehearsal: noted, passed.

import { createPublicKey, verify } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

export const TOKEN_HEADER = "Repeat-back approval v1";

// @rule:RPB-008 — the approval must verify against the pinned key and name exactly what is about to ship.
export function checkApproval({ text, publicPem, commit, name, version, repo }) {
  if (!publicPem) return { ok: false, why: "no public key pinned in the repo (.github/repeat-back.pub.pem)" };
  const lines = String(text ?? "").replace(/\r/g, "").split("\n").map((l) => l.trim()).filter(Boolean);
  const at = lines.indexOf(TOKEN_HEADER);
  if (at < 0 || lines.length < at + 3) return { ok: false, why: "the tag carries no Repeat-back approval" };
  const line = lines[at + 1];
  const sigLine = lines[at + 2];
  if (!sigLine.startsWith("sig:")) return { ok: false, why: "the approval has no signature line" };
  let good = false;
  try { good = verify(null, Buffer.from(line), createPublicKey(publicPem), Buffer.from(sigLine.slice(4), "base64")); } catch { good = false; }
  if (!good) return { ok: false, why: "the signature does not verify against the pinned key" };
  let p;
  try { p = JSON.parse(line); } catch { return { ok: false, why: "the approval is not readable" }; }
  if (p.decision !== "approve") return { ok: false, why: `the decision is ${p.decision}, not approve` };
  if (p.commit !== commit) return { ok: false, why: `approved commit ${String(p.commit).slice(0, 7)}, this run is ${String(commit).slice(0, 7)}` };
  if (p.package !== name) return { ok: false, why: `approved package ${p.package}, this run publishes ${name}` };
  if (p.version !== version) return { ok: false, why: `approved version ${p.version}, this run publishes ${version}` };
  if (repo && p.repo !== repo) return { ok: false, why: `approved for ${p.repo}, this run is ${repo}` };
  return { ok: true, payload: p };
}

function arg(k, d) { const i = process.argv.indexOf(k); return i >= 0 ? process.argv[i + 1] : d; }

function main() {
  const mode = arg("--mode", "observe");
  const dir = arg("--package-dir", ".");
  const pubPath = arg("--pub", ".github/repeat-back.pub.pem");
  const { GITHUB_REF_TYPE, GITHUB_REF_NAME, GITHUB_SHA, GITHUB_REPOSITORY } = process.env;

  if (GITHUB_REF_TYPE !== "tag") {
    console.log("Repeat-back: no tag (a manual run is a rehearsal and publishes nothing): nothing to check");
    return 0;
  }
  // actions/checkout does not bring the annotated tag object; fetch it so its message can be read.
  let text = "";
  try {
    execFileSync("git", ["fetch", "--force", "--quiet", "origin", `refs/tags/${GITHUB_REF_NAME}:refs/tags/${GITHUB_REF_NAME}`], { stdio: "inherit" });
    const type = execFileSync("git", ["cat-file", "-t", GITHUB_REF_NAME], { encoding: "utf8" }).trim();
    if (type === "tag") text = execFileSync("git", ["tag", "-l", "--format=%(contents)", GITHUB_REF_NAME], { encoding: "utf8" });
  } catch (e) { text = ""; console.log(`Repeat-back: could not read the tag: ${e.message}`); }

  const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
  const publicPem = existsSync(pubPath) ? readFileSync(pubPath, "utf8") : "";
  const r = checkApproval({ text, publicPem, commit: GITHUB_SHA, name: pkg.name, version: pkg.version, repo: GITHUB_REPOSITORY });

  if (r.ok) {
    const p = r.payload;
    console.log(`Repeat-back: APPROVED ${p.package}@${p.version} ${p.commit.slice(0, 7)} by ${p.by} at ${p.decided_at} (CI then: ${p.verdict}; request ${p.id})`);
    if (p.verdict !== "green") console.log(`::warning title=Repeat-back::approved while CI was ${p.verdict}: recorded as an override`);
    return 0;
  }
  // @rule:RPB-009 — observe warns and goes on; enforce stops the publish.
  if (mode === "enforce") { console.log(`::error title=Repeat-back::REFUSED: ${r.why}`); return 1; }
  console.log(`::warning title=Repeat-back (observe)::would refuse: ${r.why}`);
  return 0;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) process.exit(main());
