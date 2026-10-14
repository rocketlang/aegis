// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// P3: a root envelope needs a valid mandate and is capped by it (GTP-017/019/022), applied in enforce
// mode, reported in monitor mode (founder ruling 2a). Throwaway HOME; the route reads the config on
// every request, so one HOME switches between modes.

import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

const home = mkdtempSync(join(tmpdir(), "aegis-ase-mandate-"));
process.env.HOME = home;
process.env.AEGIS_DIR = join(home, ".aegis");
process.env.KAVACHOS_MUDRIKA_SECRET = "t";
mkdirSync(join(home, ".aegis"), { recursive: true });
const mode = (m: "enforce" | "monitor") => writeFileSync(join(home, ".aegis", "config.json"), JSON.stringify({ enforcement: { mode: m }, kavach: { enabled: true } }));

const { default: Fastify } = await import("fastify");
const { registerAseRoutes } = await import("../src/dashboard/routes/ase");
const { getAegisDir } = await import("../src/core/config");
const M = await import("../src/kavach/mandate");

const unsafe = !getAegisDir().startsWith(home) && !process.env.CI;
if (unsafe) console.warn(`[ase-mandate-root] SKIPPED: aegis dir resolves to ${getAegisDir()}; run this file on its own`);

const app = Fastify();
registerAseRoutes(app);
let base = "";
beforeAll(async () => {
  if (unsafe) return;
  await app.listen({ port: 0, host: "127.0.0.1" });
  base = `http://127.0.0.1:${(app.server.address() as { port: number }).port}`;
});
afterAll(async () => { await app.close(); rmSync(home, { recursive: true, force: true }); });

async function issue(body: Record<string, unknown>) {
  const r = await fetch(`${base}/api/v1/aegis/session`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  return { status: r.status, json: (await r.json()) as Record<string, unknown> };
}

describe.skipIf(unsafe)("root envelope and mandate", () => {
  test("enforce: no mandate is refused GTP-017", async () => {
    mode("enforce");
    const r = await issue({ service_key: "t", perm_mask: 0b1111, trust_mask: 0b1111 });
    expect(r.status).toBe(403);
    expect(String(r.json.error)).toContain("GTP-017");
  });

  test("enforce: a valid mandate caps the root to its mask (GTP-019)", async () => {
    mode("enforce");
    const m = M.issueMandate("root-1", { trustMask: 0b0011, scopeKey: "t", principal: "owner:test" });
    const r = await issue({ service_key: "t", mandate_id: m.mudrika_id, perm_mask: 0b1111, trust_mask: 0b1111 });
    expect(r.status).toBe(200);
    expect(r.json).toMatchObject({ perm_mask: 0b0011, mandate_id: m.mudrika_id, mandate_status: "valid" });
  });

  test("enforce: a revoked mandate is refused GTP-022", async () => {
    mode("enforce");
    const m = M.issueMandate("root-2", { trustMask: 0b0011, scopeKey: "t", principal: "owner:test" });
    M.revokeMandate(m.mudrika_id, "test");
    const r = await issue({ service_key: "t", mandate_id: m.mudrika_id, perm_mask: 0b1111 });
    expect(r.status).toBe(403);
    expect(String(r.json.error)).toContain("GTP-022");
  });

  test("monitor: no mandate is issued as before and reported missing", async () => {
    mode("monitor");
    const r = await issue({ service_key: "t", perm_mask: 0b1111, trust_mask: 0b1111 });
    expect(r.status).toBe(200);
    expect(r.json).toMatchObject({ perm_mask: 0b1111, mandate_status: "missing" });
  });

  test("monitor: a valid mandate is reported with the cap enforce would apply, mask unchanged", async () => {
    mode("monitor");
    const m = M.issueMandate("root-3", { trustMask: 0b0011, scopeKey: "t", principal: "owner:test" });
    const r = await issue({ service_key: "t", mandate_id: m.mudrika_id, perm_mask: 0b1111, trust_mask: 0b1111 });
    expect(r.json).toMatchObject({ perm_mask: 0b1111, mandate_status: "valid", would_cap_perm_mask: 0b0011 });
  });

  test("a child is narrowed by its parent and needs no mandate of its own", async () => {
    mode("enforce");
    const m = M.issueMandate("root-4", { trustMask: 0b0111, scopeKey: "t", principal: "owner:test" });
    const parent = await issue({ service_key: "t", mandate_id: m.mudrika_id, perm_mask: 0b0111 });
    const child = await issue({ service_key: "t", parent_session_id: parent.json.session_id, perm_mask: 0b1111 });
    expect(child.status).toBe(200);
    expect(child.json.perm_mask).toBe(0b0111);
  });
});
