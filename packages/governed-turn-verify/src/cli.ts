#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// gtp-check — the verifier at a local position (a hook, a launcher, a script). Reads one envelope as JSON
// on stdin, the same envelope an HTTP gate reads from headers (GTP-023), and judges it with checkTurn.
//
//   stdin           {"method","path","fields":{…}}, or any object holding that under "gtp"
//   GTP_SUBSTRATE   path to a JSON file: {"keyRegistry", "sessions", "catalog", "level"?, "windowMs"?}
//   GTP_NONCES      optional path to a JSON file of seen nonces, kept between runs (replay across calls)
//
// Exit: 0 the turn may go ahead (PASS; or any verdict at L0, which only records) · 2 refused or held
// for approval · 3 could not check (no substrate, unreadable input). The verdict is printed as JSON.

import { readFileSync, writeFileSync, renameSync } from "node:fs";
import { checkTurn, envelopeFromJson, refusalBody } from "./index.js";
import type { Substrate } from "./index.js";

function broke(msg: string): never {
  process.stderr.write(`[gtp-check] could not check: ${msg}\n`);
  process.exit(3);
}

async function main(): Promise<void> {
  const subPath = process.env.GTP_SUBSTRATE;
  if (!subPath) broke("GTP_SUBSTRATE is not set");
  let sub: Substrate;
  try { sub = JSON.parse(readFileSync(subPath, "utf8")); } catch (e) { broke(`substrate ${subPath}: ${(e as Error).message}`); }
  if (!sub.keyRegistry || !sub.sessions || !sub.catalog) broke("substrate needs keyRegistry, sessions and catalog");

  let raw: unknown;
  try { raw = JSON.parse(readFileSync(0, "utf8")); } catch { broke("stdin is not JSON"); }
  const holder = raw && typeof raw === "object" && "gtp" in (raw as object) ? (raw as { gtp: unknown }).gtp : raw;
  const env = envelopeFromJson(holder) ?? { method: "", path: "", fields: {} }; // no envelope → step 0 answers 428

  const noncesPath = process.env.GTP_NONCES;
  let seen = new Map<string, number>();
  if (noncesPath) {
    try { seen = new Map(Object.entries(JSON.parse(readFileSync(noncesPath, "utf8")) as Record<string, number>)); } catch { /* first run */ }
  }
  const r = await checkTurn(env, { ...sub, seenNonces: seen });
  if (noncesPath) {
    const tmp = `${noncesPath}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify(Object.fromEntries(seen)), { mode: 0o600 });
    renameSync(tmp, noncesPath);
  }

  process.stdout.write(JSON.stringify({ ...r, ...(r.verdict.status === "PASS" ? {} : { refusal: refusalBody(r.turnId, r.verdict) }) }) + "\n");
  if (r.verdict.status === "PASS" || !r.enforced) {
    if (r.verdict.status !== "PASS") process.stderr.write(`[gtp-check] L0: would be ${r.verdict.status} (${r.verdict.rule}): ${r.verdict.detail}\n`);
    process.exit(0);
  }
  process.stderr.write(`[gtp-check] ${r.verdict.status} ${r.verdict.code} (${r.verdict.rule}): ${r.verdict.detail}\n`);
  process.exit(2);
}

main().catch((e) => broke(String((e as Error)?.message ?? e)));
