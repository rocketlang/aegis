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
}

export function epochOf(table: DoorTable, id: string): number {
  const n = table.open_epochs[id];
  return Number.isInteger(n) && n > 0 ? n : 0;
}

// The bulkhead only ever READS this file. Writing it is a person's act; the shield refuses tool writes (KAV-096).
export function loadDoors(path: string): DoorTable {
  if (!existsSync(path)) return { doors: [], errors: [], open_epochs: {} };
  let raw: unknown;
  try { raw = JSON.parse(readFileSync(path, "utf-8")); } catch (e) {
    return { doors: [], errors: [`doors file is not JSON: ${(e as Error).message}`], open_epochs: {} };
  }
  const list = Array.isArray(raw) ? raw : (raw as { doors?: unknown })?.doors;
  if (!Array.isArray(list)) return { doors: [], errors: ["doors file must be an array or { doors: [...] }"], open_epochs: {} };
  const oe = Array.isArray(raw) ? {} : (raw as { open_epochs?: unknown }).open_epochs;
  const open_epochs: Record<string, number> = oe && typeof oe === "object" && !Array.isArray(oe) ? (oe as Record<string, number>) : {};
  const doors: Door[] = [];
  const errors: string[] = [];
  const ids = new Set<string>();
  list.forEach((d: any, i: number) => {
    const where = `door #${i + 1}${d?.id ? ` (${d.id})` : ""}`;
    if (!d || typeof d.id !== "string" || !d.id) return errors.push(`${where}: id required`);
    if (ids.has(d.id)) return errors.push(`${where}: duplicate id`);
    if (typeof d.from !== "string" || typeof d.to !== "string") return errors.push(`${where}: from and to required`);
    if (d.from === d.to) return errors.push(`${where}: a door joins two different compartments`);
    if (!Array.isArray(d.kinds) || d.kinds.length === 0) return errors.push(`${where}: kinds required`);
    const bad = d.kinds.filter((k: string) => !(KINDS as readonly string[]).includes(k));
    if (bad.length) return errors.push(`${where}: unknown kind ${bad.join(", ")} (only ${KINDS.join(", ")}; there is no COMMAND)`);
    // A door that declares something invalid is shut, not half-open: it is dropped, and the error is reported.
    ids.add(d.id);
    doors.push(d as Door);
  });
  return { doors, errors, open_epochs };
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
