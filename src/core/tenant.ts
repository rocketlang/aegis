// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// [EE] AEGIS — Multi-Tenant Isolation
// Scopes all budget, audit, and policy records by tenant_id.
// Default tenant: "default" (single-user / OSS deployment).
// xShieldAI enterprise: each customer org gets an isolated tenant_id.
// @rule:KAV-071 per-tenant budget isolation
// @rule:KAV-072 per-tenant audit log isolation
// @rule:KAV-073 per-tenant policy scoping

import { existsSync, mkdirSync, writeFileSync, readFileSync } from "fs";
import { join } from "path";
import { getAegisDir } from "./config";

export const DEFAULT_TENANT = "default";

export interface TenantConfig {
  tenant_id: string;
  display_name: string;
  created_at: string;
  budget: {
    daily_limit_usd: number;
    weekly_limit_usd: number;
    monthly_limit_usd: number;
    session_limit_usd: number;
    spawn_limit_per_session: number;
  };
  enforcement: {
    mode: "alert" | "enforce";
  };
  kavach: {
    enabled: boolean;
    notify_channel: string;
    dual_control_enabled: boolean;
  };
}

const DEFAULT_TENANT_CONFIG: Omit<TenantConfig, "tenant_id" | "created_at"> = {
  display_name: "Default",
  budget: {
    daily_limit_usd: 100,
    weekly_limit_usd: 400,
    monthly_limit_usd: 1200,
    session_limit_usd: 10,
    spawn_limit_per_session: 20,
  },
  enforcement: { mode: "alert" },
  kavach: { enabled: true, notify_channel: "telegram", dual_control_enabled: false },
};

function tenantsDir(): string {
  return join(getAegisDir(), "tenants");
}

function tenantConfigPath(tenantId: string): string {
  return join(tenantsDir(), `${tenantId}.json`);
}

export function ensureTenant(tenantId: string): TenantConfig {
  const dir = tenantsDir();
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });

  const path = tenantConfigPath(tenantId);
  if (existsSync(path)) {
    return JSON.parse(readFileSync(path, "utf-8")) as TenantConfig;
  }

  const cfg: TenantConfig = {
    ...DEFAULT_TENANT_CONFIG,
    tenant_id: tenantId,
    display_name: tenantId === DEFAULT_TENANT ? "Default" : tenantId,
    created_at: new Date().toISOString(),
  };
  writeFileSync(path, JSON.stringify(cfg, null, 2));
  return cfg;
}

export function getTenantConfig(tenantId: string): TenantConfig {
  return ensureTenant(tenantId);
}

export function saveTenantConfig(cfg: TenantConfig): void {
  const dir = tenantsDir();
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  writeFileSync(tenantConfigPath(cfg.tenant_id), JSON.stringify(cfg, null, 2));
}

export function listTenants(): TenantConfig[] {
  const dir = tenantsDir();
  if (!existsSync(dir)) return [ensureTenant(DEFAULT_TENANT)];
  const { readdirSync } = require("fs");
  return readdirSync(dir)
    .filter((f: string) => f.endsWith(".json"))
    .map((f: string) => {
      try { return JSON.parse(readFileSync(join(dir, f), "utf-8")) as TenantConfig; }
      catch { return null; }
    })
    .filter(Boolean) as TenantConfig[];
}

export function deleteTenant(tenantId: string): boolean {
  if (tenantId === DEFAULT_TENANT) return false; // cannot delete default
  const path = tenantConfigPath(tenantId);
  if (!existsSync(path)) return false;
  const { unlinkSync } = require("fs");
  unlinkSync(path);
  return true;
}

// Fastify request helper — extracts tenant_id from X-Tenant-ID header, defaults to "default"
export function extractTenantId(req: { headers: Record<string, string | string[] | undefined> }): string {
  const header = req.headers["x-tenant-id"];
  if (!header) return DEFAULT_TENANT;
  const tid = Array.isArray(header) ? header[0] : header;
  // Sanitise: alphanumeric + hyphen/underscore only, max 64 chars
  return tid.replace(/[^a-zA-Z0-9\-_]/g, "").slice(0, 64) || DEFAULT_TENANT;
}
