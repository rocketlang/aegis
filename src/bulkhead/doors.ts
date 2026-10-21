// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// Doors: one-way, declared by a person, shut unless declared.
// @rule:BLK-001 no message crosses a compartment boundary except through a declared door
// @rule:BLK-002 doors are one-way and shut unless declared in the doors file (only a person writes it)

import { existsSync, readFileSync, renameSync, writeFileSync } from "fs";
import { KINDS, type Door } from "./types";

export interface DoorTable {
  doors: Door[];
  errors: string[];
  // @rule:BLK-012 a person re-opens a closed door or compartment by raising its epoch here
  open_epochs: Record<string, number>;
  // P3: which compartments belong to which party; a compartment no party lists is the home party's
  home: string;
  parties: Record<string, { compartments: string[] }>;
  // P4: the data paths each compartment reads from, declared by a person (BLK-018)
  data_paths: Record<string, string[]>;
}

const EMPTY_TABLE = (errors: string[] = []): DoorTable => ({ doors: [], errors, open_epochs: {}, home: "home", parties: {}, data_paths: {} });

export function epochOf(table: DoorTable, id: string): number {
  const n = table.open_epochs[id];
  return Number.isInteger(n) && n > 0 ? n : 0;
}

// The bulkhead only ever READS this file. Writing it is a person's act; the shield refuses tool writes (KAV-096).
export function loadDoors(path: string): DoorTable {
  if (!existsSync(path)) return EMPTY_TABLE();
  let raw: unknown;
  try { raw = JSON.parse(readFileSync(path, "utf-8")); } catch (e) {
    return EMPTY_TABLE([`doors file is not JSON: ${(e as Error).message}`]);
  }
  const list = Array.isArray(raw) ? raw : (raw as { doors?: unknown })?.doors;
  if (!Array.isArray(list)) return EMPTY_TABLE(["doors file must be an array or { doors: [...] }"]);
  const obj = Array.isArray(raw) ? {} : (raw as { open_epochs?: unknown; home?: unknown; parties?: unknown; data_paths?: unknown });
  const oe = obj.open_epochs;
  const open_epochs: Record<string, number> = oe && typeof oe === "object" && !Array.isArray(oe) ? (oe as Record<string, number>) : {};
  const doors: Door[] = [];
  const errors: string[] = [];
  const ids = new Set<string>();

  const home = typeof obj.home === "string" && obj.home ? obj.home : "home";
  const parties: DoorTable["parties"] = {};
  const owner = new Map<string, string[]>();
  if (obj.parties && typeof obj.parties === "object" && !Array.isArray(obj.parties)) {
    for (const [name, p] of Object.entries(obj.parties as Record<string, any>)) {
      if (name === home) { errors.push(`party ${name}: the home party lists no compartments (unlisted ones are home)`); continue; }
      if (!/^[a-z0-9][a-z0-9_-]{0,63}$/i.test(name)) { errors.push(`party ${name}: name must be letters, digits, - or _`); continue; }
      const cs = Array.isArray(p?.compartments) ? p.compartments.filter((c: unknown) => typeof c === "string") : [];
      parties[name] = { compartments: cs };
      for (const c of cs) owner.set(c, [...(owner.get(c) ?? []), name]);
    }
  }
  const twice = new Set([...owner].filter(([, o]) => o.length > 1).map(([c]) => c));
  for (const c of twice) errors.push(`compartment ${c} is listed by parties ${owner.get(c)!.join(" and ")}: its doors are shut`);
  const partyOfC = (c: string) => owner.get(c)?.[0] ?? home;

  const data_paths: DoorTable["data_paths"] = {};
  if (obj.data_paths && typeof obj.data_paths === "object" && !Array.isArray(obj.data_paths)) {
    for (const [c, ps] of Object.entries(obj.data_paths as Record<string, unknown>)) {
      if (!Array.isArray(ps)) { errors.push(`data_paths ${c}: must be a list`); continue; }
      data_paths[c] = ps.filter((p): p is string => typeof p === "string" && p.length > 0 && p.length <= 200);
    }
  }
  list.forEach((d: any, i: number) => {
    const where = `door #${i + 1}${d?.id ? ` (${d.id})` : ""}`;
    if (!d || typeof d.id !== "string" || !d.id) return errors.push(`${where}: id required`);
    if (ids.has(d.id)) return errors.push(`${where}: duplicate id`);
    if (typeof d.from !== "string" || typeof d.to !== "string") return errors.push(`${where}: from and to required`);
    if (d.from === d.to) return errors.push(`${where}: a door joins two different compartments`);
    if (!Array.isArray(d.kinds) || d.kinds.length === 0) return errors.push(`${where}: kinds required`);
    const bad = d.kinds.filter((k: string) => !(KINDS as readonly string[]).includes(k));
    if (bad.length) return errors.push(`${where}: unknown kind ${bad.join(", ")} (only ${KINDS.join(", ")}; there is no COMMAND)`);
    if (twice.has(d.from) || twice.has(d.to)) return errors.push(`${where}: joins a compartment two parties claim`);
    if (d.check) {
      // @rule:BLK-017 a check door carries the checker's FINDING, and its verdict must be able to pass
      if (!d.kinds.includes("FINDING")) return errors.push(`${where}: a check door carries FINDING`);
      if (Array.isArray(d.fields) && !d.fields.includes("verdict")) return errors.push(`${where}: a check door's fields must include verdict`);
    }
    if (partyOfC(d.from) !== partyOfC(d.to)) {
      // @rule:BLK-015 a door between parties carries only the fields it lists; no list = shut
      if (!Array.isArray(d.fields) || d.fields.length === 0) return errors.push(`${where}: a door between parties must list its fields (BLK-015)`);
      // @rule:BLK-014 its terms carry an end date, which the other party signs too
      if (typeof d.valid_until !== "string" || !Number.isFinite(Date.parse(d.valid_until))) return errors.push(`${where}: a door between parties needs valid_until (BLK-014)`);
    }
    // A door that declares something invalid is shut, not half-open: it is dropped, and the error is reported.
    ids.add(d.id);
    doors.push(d as Door);
  });
  return { doors, errors, open_epochs, home, parties, data_paths };
}

// One-way: a door from A to B never lets B speak to A.
export function findDoor(table: DoorTable, from: string, to: string): Door | null {
  return table.doors.find((d) => d.from === from && d.to === to) ?? null;
}

// A person's act (BLK-012): raise the open epoch of a door or compartment. Run from a person's
// terminal; the shield refuses it as a tool call, and refuses any tool write to the file (KAV-096).
export function raiseOpenEpoch(path: string, id: string): number {
  let raw: any = existsSync(path) ? JSON.parse(readFileSync(path, "utf-8")) : { doors: [] };
  if (Array.isArray(raw)) raw = { doors: raw };
  raw.open_epochs = raw.open_epochs && typeof raw.open_epochs === "object" ? raw.open_epochs : {};
  const next = (Number.isInteger(raw.open_epochs[id]) && raw.open_epochs[id] > 0 ? raw.open_epochs[id] : 0) + 1;
  raw.open_epochs[id] = next;
  writeFileSync(path + ".tmp", JSON.stringify(raw, null, 2) + "\n");
  renameSync(path + ".tmp", path);
  return next;
}
