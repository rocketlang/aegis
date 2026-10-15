// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// Publishing the flow-receipt chain's head in a public log (gap 3 of the flow guardrails; founder's choice
// 2026-10-15: Sigstore's public log, with a key of our own kept under his control).
//
// One entry = one web call, no account: Sigstore's transparency log (Rekor), kind "hashedrekord". By a rule
// anyone can redo: the artifact is the head's hash as 64 hex characters of text, no line end; the entry holds
// SHA-256 of that text, an ECDSA P-256 signature over it, and our public key. Carried over from the tank
// experiment's tested sender (diksha record 15.87).
//
// What an anchor gives: once a head is in the log, a later chain on this box must still contain it at the
// same place, or `aegis flow-receipts verify` says the chain was cut. What it does not give: that a receipt
// was true, or that this box was honest before the anchor; and a key on this box is as safe as the box.
// Every entry is permanent and public. Sending is a person's step: the key is theirs.

import { spawnSync } from "child_process";
import { createHash, createPublicKey, generateKeyPairSync, sign, verify } from "crypto";
import { appendFileSync, existsSync, readFileSync, statSync, writeFileSync } from "fs";
import { anchorsPath, readAnchors } from "./receipt-chain";
import type { AnchorRecord } from "./receipt-chain";
export { readAnchors };
export type { AnchorRecord };

export const REKOR_URL = "https://rekor.sigstore.dev/api/v1/log/entries";
const sha = (s: string): string => createHash("sha256").update(s, "utf8").digest("hex");


/** Make the key pair. Refuses to overwrite. The private half is written owner-only and never printed. */
export function makeKey(out: string): { publicPem: string; fingerprint: string } {
  if (existsSync(out)) throw new Error(`${out} exists; refusing to overwrite a key`);
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1", publicKeyEncoding: { type: "spki", format: "pem" }, privateKeyEncoding: { type: "pkcs8", format: "pem" } });
  writeFileSync(out, privateKey, { mode: 0o600 });
  return { publicPem: publicKey, fingerprint: sha(publicKey.replace(/\s/g, "")).slice(0, 16) };
}

/** Read the private key, refusing one that anyone but its owner can read. */
export function loadKey(path: string): string {
  const mode = statSync(path).mode & 0o777;
  if (mode & 0o077) throw new Error(`${path} can be read by others (mode ${mode.toString(8)}); chmod 600 it first`);
  return readFileSync(path, "utf8");
}

export const publicOf = (privatePem: string): string => createPublicKey(privatePem).export({ type: "spki", format: "pem" }) as string;

export function entryBody(sum: string, privatePem: string): string {
  if (!/^[0-9a-f]{64}$/.test(sum)) throw new Error("not a checksum of 64 hex characters");
  const sig = sign("sha256", Buffer.from(sum, "utf8"), privatePem).toString("base64");
  return JSON.stringify({ apiVersion: "0.0.1", kind: "hashedrekord", spec: { data: { hash: { algorithm: "sha256", value: sha(sum) } },
    signature: { content: sig, publicKey: { content: Buffer.from(publicOf(privatePem)).toString("base64") } } } });
}

interface Entry { uuid: string; index: number | null; at: number | null; spec: any }
function entryOf(reply: unknown): Entry | null {
  try {
    const [uuid, e] = Object.entries(reply as Record<string, any>)[0];
    return { uuid, index: e.logIndex ?? null, at: e.integratedTime ?? null, spec: JSON.parse(Buffer.from(e.body, "base64").toString()).spec };
  } catch { return null; }
}

/** Does a returned entry hold OUR hash under OUR key, with a signature that verifies? The reasons it does not. */
export function checkEntry(entry: Entry | null, sum: string, publicPem: string): string[] {
  const why: string[] = [];
  if (!entry || !entry.spec) return ["no entry"];
  if (entry.spec.data?.hash?.value !== sha(sum)) why.push("the entry's hash is not the SHA-256 of our head");
  const pem = Buffer.from(String(entry.spec.signature?.publicKey?.content ?? ""), "base64").toString();
  if (pem.replace(/\s/g, "") !== publicPem.replace(/\s/g, "")) why.push("the entry's key is not our key");
  let ok = false;
  try { ok = verify("sha256", Buffer.from(sum, "utf8"), publicPem, Buffer.from(String(entry.spec.signature?.content ?? ""), "base64")); } catch { /* not verified */ }
  if (!ok) why.push("the signature does not verify under our key");
  return why;
}

/** One sending, through curl (Node's fetch times out on this box where curl does not). Never throws. */
export function sendHead(sum: string, privatePem: string, url = REKOR_URL, timeoutMs = 15000): { ok: boolean; http: number; entry: Entry | null; problems: string[] } {
  const r = spawnSync("curl", ["-s", "-m", String(Math.ceil(timeoutMs / 1000)), "-w", "\n%{http_code}", url, "-H", "content-type: application/json", "-H", "accept: application/json", "-d", "@-"],
    { input: entryBody(sum, privatePem), encoding: "utf8", timeout: timeoutMs + 2000 });
  const all = String(r.stdout ?? ""), cut = all.lastIndexOf("\n");
  const raw = cut < 0 ? "" : all.slice(0, cut), http = parseInt(all.slice(cut + 1), 10) || 0;
  if (r.status !== 0) return { ok: false, http, entry: null, problems: [`curl ended ${r.status}`] };
  let reply: unknown = null;
  try { reply = JSON.parse(raw); } catch { /* not JSON */ }
  const entry = http === 201 ? entryOf(reply) : null;
  if (!entry) return { ok: false, http, entry: null, problems: [`the log answered HTTP ${http}`] };
  const problems = checkEntry(entry, sum, publicOf(privatePem));
  return { ok: problems.length === 0, http, entry, problems };
}

export function recordAnchor(rec: AnchorRecord): void {
  appendFileSync(anchorsPath(), JSON.stringify(rec) + "\n", { mode: 0o600 });
}
