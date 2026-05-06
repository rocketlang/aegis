// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// AEGIS Enforcement Registry — services.json reader with TIER-A pilot filter
//
// @rule:AEG-E-007 — pilot scope is TIER-A services only
// @rule:BMOS-005  — services.json is authoritative; cache validated by mtime every 60s

import { readFileSync, statSync, existsSync } from "fs";
import { join } from "path";
import type { ServiceRegistryEntry, RuntimeReadinessTier } from "./types";

const SERVICES_JSON_PATH = join(
  process.env.HOME ?? "/root",
  ".ankr/config/services.json"
);

const CACHE_TTL_MS = 60_000;

// TIER-A services identified in Batch 15 — the enforcement pilot set
// Batch 61 (2026-05-06): freightbox + mari8x-community added (TIER-B, human_gate_required=true, BR-5)
// @rule:AEG-E-007 — only these services enter live enforcement pilot
export const TIER_A_PILOT_SET = new Set([
  "granthx",
  "stackpilot",
  "ankrclaw",
  "carbonx",
  "parali-central",
  "ankr-doctor",
  "domain-capture",
  "pramana",
  "ship-slm",
  "chief-slm",
  "chirpee",
  "puranic-os",
  // Batch 61 additions — TIER-B, human_gate=true, BR-5
  "freightbox",
  "mari8x-community",
]);

interface RegistryCache {
  entries: Record<string, ServiceRegistryEntry>;
  loaded_at: number;
  mtime: number;
}

let _cache: RegistryCache | null = null;

// @rule:AEG-E-007 pilot scope enforced here — non-TIER-A services return monitor-only entry
export function loadRegistry(): Record<string, ServiceRegistryEntry> {
  const now = Date.now();

  if (_cache && now - _cache.loaded_at < CACHE_TTL_MS) return _cache.entries;

  let mtime = 0;
  try { mtime = statSync(SERVICES_JSON_PATH).mtimeMs; } catch {}
  if (_cache && mtime === _cache.mtime) {
    _cache.loaded_at = now;
    return _cache.entries;
  }

  const entries: Record<string, ServiceRegistryEntry> = {};

  if (!existsSync(SERVICES_JSON_PATH)) {
    _cache = { entries, loaded_at: now, mtime: 0 };
    return entries;
  }

  try {
    const raw = JSON.parse(readFileSync(SERVICES_JSON_PATH, "utf-8"));
    const svcs: Record<string, Record<string, unknown>> = raw.services ?? raw;

    for (const [key, val] of Object.entries(svcs)) {
      if (!val || typeof val !== "object") continue;

      const tier = (val.runtime_readiness as { tier?: string } | undefined)?.tier;

      entries[key] = {
        trust_mask: typeof val.trust_mask === "number" ? val.trust_mask : 0,
        authority_class: (val.authority_class as string ?? "read_only") as ServiceRegistryEntry["authority_class"],
        governance_blast_radius: typeof val.governance_blast_radius === "string"
          ? val.governance_blast_radius : "BR-0",
        human_gate_required: val.human_gate_required === true,
        needs_code_scan: val.needs_code_scan === true,
        aegis_gate: (val.aegis_gate as ServiceRegistryEntry["aegis_gate"]) ?? {
          overall: "ALLOW",
          op1_read: "ALLOW",
          op2_write: "ALLOW",
          op3_execute: "ALLOW",
          op4_deploy: "ALLOW",
          op5_approve: "ALLOW",
        },
        runtime_readiness: {
          tier: (tier as RuntimeReadinessTier) ?? "TIER-C",
          description: (val.runtime_readiness as { description?: string } | undefined)?.description ?? "",
          reason: (val.runtime_readiness as { reason?: string } | undefined)?.reason ?? "",
        },
        semantic_mask: typeof val.semantic_mask === "number" ? val.semantic_mask : 0,
      };
    }
  } catch { /* unreadable — return empty; enforcement will WARN not BLOCK */ }

  _cache = { entries, loaded_at: now, mtime };
  return entries;
}

export function getServiceEntry(serviceId: string): ServiceRegistryEntry | null {
  return loadRegistry()[serviceId] ?? null;
}

export function isInPilotScope(serviceId: string): boolean {
  return TIER_A_PILOT_SET.has(serviceId);
}

export function pilotSet(): string[] {
  return [...TIER_A_PILOT_SET];
}

export function registrySize(): number {
  return Object.keys(loadRegistry()).length;
}

export function cacheAge(): number {
  return _cache ? Date.now() - _cache.loaded_at : -1;
}

export function invalidateCache(): void {
  _cache = null;
}
