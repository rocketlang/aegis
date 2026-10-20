// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// Doors: one-way, declared by a person, shut unless declared.
// @rule:BLK-001 no message crosses a compartment boundary except through a declared door
// @rule:BLK-002 doors are one-way and shut unless declared in the doors file (only a person writes it)

import { existsSync, readFileSync } from "fs";
import { KINDS, type Door } from "./types";

export interface DoorTable {
  doors: Door[];
  errors: string[];
}

// The bulkhead only ever READS this file. Writing it is a person's act (shield enforcement is P2).
export function loadDoors(path: string): DoorTable {
  if (!existsSync(path)) return { doors: [], errors: [] };
  let raw: unknown;
  try { raw = JSON.parse(readFileSync(path, "utf-8")); } catch (e) {
    return { doors: [], errors: [`doors file is not JSON: ${(e as Error).message}`] };
  }
  const list = Array.isArray(raw) ? raw : (raw as { doors?: unknown })?.doors;
  if (!Array.isArray(list)) return { doors: [], errors: ["doors file must be an array or { doors: [...] }"] };
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
  return { doors, errors };
}

// One-way: a door from A to B never lets B speak to A.
export function findDoor(table: DoorTable, from: string, to: string): Door | null {
  return table.doors.find((d) => d.from === from && d.to === to) ?? null;
}
