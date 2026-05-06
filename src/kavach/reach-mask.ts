// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// @rule:KAV-088 reach_mask enforcement — cross-service authorization gate
//
// Additive migration: services without reach_permissions skip check.
// BitMask OS paper: `(caller_perm_mask & target.reach_permissions) !== 0` → allow.
// Invariant: reach_permissions == 0 means "any caller allowed" (default for unenrolled services).

import { existsSync, readFileSync } from "fs";

const SERVICES_JSON_PATH = "/root/.ankr/config/services.json";
const CACHE_TTL_MS = 60_000;

interface ServiceEntry {
  port?: number;
  reach_permissions?: number;  // ankr-reach-32bit-v1; 0 / absent = any caller
}

let _cache: Record<string, ServiceEntry> | null = null;
let _cacheTs = 0;

function loadServicesIndex(): Record<string, ServiceEntry> {
  const now = Date.now();
  if (_cache && now - _cacheTs < CACHE_TTL_MS) return _cache;
  try {
    const raw = readFileSync(SERVICES_JSON_PATH, "utf-8");
    const parsed = JSON.parse(raw);
    _cache = typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
    _cacheTs = now;
    return _cache!;
  } catch {
    return {};
  }
}

function resolveByPort(port: number): { service_key: string; reach_permissions: number } | null {
  const index = loadServicesIndex();
  for (const [key, entry] of Object.entries(index)) {
    if (key.startsWith("_")) continue;
    if (typeof entry !== "object" || entry === null) continue;
    if (entry.port === port && typeof entry.reach_permissions === "number" && entry.reach_permissions !== 0) {
      return { service_key: key, reach_permissions: entry.reach_permissions };
    }
  }
  return null; // no reach_permissions → skip (additive migration)
}

function extractPort(url: string): number | null {
  try {
    const u = new URL(url);
    const p = parseInt(u.port, 10);
    return isNaN(p) ? null : p;
  } catch {
    const m = url.match(/:(\d{4,5})/);
    return m ? parseInt(m[1], 10) : null;
  }
}

function extractUrlsFromBash(command: string): string[] {
  const urls: string[] = [];
  const matches = command.matchAll(/https?:\/\/[^\s'"`,)]+/g);
  for (const m of matches) urls.push(m[0]);
  return urls;
}

export interface ReachCheckResult {
  checked: boolean;       // false = no reach_permissions enrolled — skip
  allowed: boolean;
  target_service: string | null;
  target_port: number | null;
  caller_mask: number;
  required_mask: number;
  rule_ref: "KAV-088";
}

const SKIP: ReachCheckResult = {
  checked: false, allowed: true, target_service: null,
  target_port: null, caller_mask: 0, required_mask: 0, rule_ref: "KAV-088",
};

// @rule:KAV-088 check caller perm_mask against target service's reach_permissions
export function checkReachMask(callerPermMask: number, url: string): ReachCheckResult {
  if (!existsSync(SERVICES_JSON_PATH)) return SKIP;
  const port = extractPort(url);
  if (!port) return SKIP;
  const service = resolveByPort(port);
  if (!service) return SKIP; // additive migration — unenrolled service, allow

  return {
    checked: true,
    allowed: (callerPermMask & service.reach_permissions) !== 0,
    target_service: service.service_key,
    target_port: port,
    caller_mask: callerPermMask,
    required_mask: service.reach_permissions,
    rule_ref: "KAV-088",
  };
}

// Scan all URLs embedded in a bash command (curl, wget, etc.)
export function checkBashReachMask(callerPermMask: number, command: string): ReachCheckResult {
  for (const url of extractUrlsFromBash(command)) {
    const result = checkReachMask(callerPermMask, url);
    if (result.checked) return result; // first enrolled service match is authoritative
  }
  return SKIP;
}
