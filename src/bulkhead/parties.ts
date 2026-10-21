// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// Doors between parties (P3): two keys, listed fields, a bell-book copy per party.
// @rule:BLK-YK-005 a door between companies is a contract: both sides sign the same terms
// @rule:INF-BLK-005 on one host root can still delete either side; the signature stops only a forged consent
//
// Layout under the bulkhead dir (all of it the shield's own files, KAV-096; a person places them):
//   parties/<party>/party.pub                      the party's ed25519 public key (PEM)
//   parties/<party>/declarations/<door-id>.json    { terms, signature } signed by that party
//   parties/<party>/bell-book.jsonl                that party's copy of the rows about its doors (BLK-016)

import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify, createHash } from "crypto";
import { existsSync, readFileSync } from "fs";
import { join } from "path";
import { canonical } from "./bell-book";
import type { Door } from "./types";
import type { DoorTable } from "./doors";

export interface Terms {
  id: string;
  from: string;
  to: string;
  kinds: string[];
  fields: string[];
  valid_until: string;
}

export interface Declaration { terms: Terms; signature: string }

export type PartyCheck =
  | { ok: true; parties: string[] }
  | { ok: false; rule: string; reason: string; parties: string[] };

export function partiesDir(dir: string): string { return join(dir, "parties"); }

// A compartment belongs to the party that lists it, else to the home party.
// null = listed by two parties: every door touching it is shut (doors.ts drops them).
export function partyOf(table: DoorTable, compartment: string): string | null {
  const owners = Object.entries(table.parties).filter(([, p]) => p.compartments.includes(compartment)).map(([n]) => n);
  if (owners.length > 1) return null;
  return owners[0] ?? table.home;
}

// The parties other than home that must have signed this door; [] for a door inside one party.
export function foreignParties(table: DoorTable, door: Pick<Door, "from" | "to">): string[] {
  const set = new Set([partyOf(table, door.from), partyOf(table, door.to)].filter((p): p is string => p !== null));
  set.delete(table.home);
  return [...set].sort();
}

// What both sides sign. Order of kinds and fields does not matter; rates and depth stay each side's own.
export function termsOf(door: Door): Terms {
  return {
    id: door.id,
    from: door.from,
    to: door.to,
    kinds: [...door.kinds].sort(),
    fields: [...(door.fields ?? [])].sort(),
    valid_until: String(door.valid_until ?? ""),
  };
}

export function keygen(): { publicKey: string; privateKey: string } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKey: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKey: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
}

// Run by the other party, on its own machine, with its own key.
export function signTerms(terms: Terms, privateKeyPem: string): Declaration {
  const t = termsOf(terms as unknown as Door);
  const signature = sign(null, Buffer.from(canonical(t)), createPrivateKey(privateKeyPem)).toString("base64");
  return { terms: t, signature };
}

export function fingerprint(publicKeyPem: string): string {
  const der = createPublicKey(publicKeyPem).export({ type: "spki", format: "der" });
  return createHash("sha256").update(der).digest("hex").slice(0, 16);
}

// @rule:BLK-014 a door between parties holds only when every other party signed the same terms,
// with the key a person placed for it, and the terms are still valid. Checked at every decision.
export function checkParties(dir: string, table: DoorTable, door: Door, now: number): PartyCheck {
  const parties = foreignParties(table, door);
  if (parties.length === 0) return { ok: true, parties };
  const ours = termsOf(door);
  const until = Date.parse(ours.valid_until);
  if (!Number.isFinite(until)) return { ok: false, rule: "BLK-014", reason: `door ${door.id} between parties has no valid_until`, parties };
  if (until <= now) return { ok: false, rule: "BLK-014", reason: `door ${door.id} expired at ${ours.valid_until}`, parties };
  for (const p of parties) {
    const base = join(partiesDir(dir), p);
    const pubPath = join(base, "party.pub");
    const decPath = join(base, "declarations", `${door.id}.json`);
    if (!existsSync(pubPath)) return { ok: false, rule: "BLK-014", reason: `no public key placed for party ${p}`, parties };
    if (!existsSync(decPath)) return { ok: false, rule: "BLK-014", reason: `party ${p} has not signed door ${door.id}`, parties };
    let dec: Declaration;
    let pub: string;
    try {
      dec = JSON.parse(readFileSync(decPath, "utf-8"));
      pub = readFileSync(pubPath, "utf-8");
    } catch (e) {
      return { ok: false, rule: "BLK-014", reason: `party ${p}'s declaration for ${door.id} cannot be read: ${(e as Error).message}`, parties };
    }
    if (!dec || typeof dec.signature !== "string" || !dec.terms) return { ok: false, rule: "BLK-014", reason: `party ${p}'s declaration for ${door.id} is not { terms, signature }`, parties };
    // Verify what they signed, then compare it with what we declared: both keys turn on the same terms.
    let good = false;
    try {
      good = verify(null, Buffer.from(canonical(dec.terms)), createPublicKey(pub), Buffer.from(dec.signature, "base64"));
    } catch { good = false; }
    if (!good) return { ok: false, rule: "BLK-014", reason: `party ${p}'s signature on ${door.id} does not verify under its placed key`, parties };
    if (canonical(termsOf(dec.terms as unknown as Door)) !== canonical(ours)) {
      return { ok: false, rule: "BLK-014", reason: `party ${p} signed different terms for ${door.id} than our doors file declares`, parties };
    }
  }
  return { ok: true, parties };
}

// ── Parcels: messages between hosts, store and forward (P5) ─────────────────────────────────────
// @rule:BLK-021 signed by the sending party's key, numbered and chained for each pair of parties
// @rule:BLK-YK-007 a parcel waits for whatever link there is; the bulkhead opens no listening port
// @rule:INF-BLK-007 a parcel proves which party's key signed it, not which of its agents wrote a message

export interface Parcel {
  v: 1;
  from_party: string;
  to_party: string;
  seq: number;
  prev_hash: string;          // hash of the parcel before it between these two parties; "" for the first
  created_at: string;
  envelopes: Array<Record<string, unknown>>;
  sig: string;
}

export function parcelHash(p: Parcel): string {
  return createHash("sha256").update(canonical(p)).digest("hex");
}

export function signParcel(p: Omit<Parcel, "sig">, privateKeyPem: string): Parcel {
  const sig = sign(null, Buffer.from(canonical(p)), createPrivateKey(privateKeyPem)).toString("base64");
  return { ...p, sig };
}

export function verifyParcelSig(p: Parcel, publicKeyPem: string): boolean {
  try {
    const { sig, ...rest } = p;
    return typeof sig === "string" && verify(null, Buffer.from(canonical(rest)), createPublicKey(publicKeyPem), Buffer.from(sig, "base64"));
  } catch { return false; }
}
