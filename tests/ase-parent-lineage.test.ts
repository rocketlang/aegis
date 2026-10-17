// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// ASE parent lineage — does a child envelope stay inside its parent? (design doc
// xshieldai-agentic-flow--logics--provisional--2026-10-14.md, gap G5, rule GTP-021)
//
// POST /api/v1/aegis/session narrows a child to `parent.perm_mask & requested` (ASE-005 / KAV-065),
// but only when the named parent is found. These tests pin both halves:
//   - control: a real parent narrows the child;
//   - the hole: a parent_session_id that names nothing must not hand the child its whole request.
//
// Runs under a throwaway HOME: aegis keeps aegis.db at $HOME/.aegis, so HOME is set before any
// aegis module loads, and the file refuses to run against /root.

import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

const scratchHome = mkdtempSync(join(tmpdir(), "aegis-ase-lineage-"));
process.env.HOME = scratchHome;
// Put back in afterAll: bun runs every test file in one process, and a leaked AEGIS_DIR sends
// the next file's stores here (it broke the approval tests in destructive-hardening, 2026-10-17).
const AEGIS_DIR_BEFORE = process.env.AEGIS_DIR;
process.env.AEGIS_DIR = join(scratchHome, ".aegis");

const { default: Fastify } = await import("fastify");
const { registerAseRoutes } = await import("../src/dashboard/routes/ase");
const { getDbPath } = await import("../src/core/config");

// Bun shares loaded modules across test files, and aegis fixes its home when config first loads. In a
// full-suite run another file may have loaded it under the real HOME. Run only where the database is
// under the scratch HOME, or on a CI runner (a throwaway machine); anywhere else skip, and say why.
const dbPath = getDbPath();
const unsafe = !dbPath.startsWith(scratchHome) && !process.env.CI;
if (unsafe) console.warn(`[ase-parent-lineage] SKIPPED: database resolves to ${dbPath}, not the scratch HOME; run this file on its own`);

const app = Fastify();
registerAseRoutes(app);
let base = "";

beforeAll(async () => {
  if (unsafe) return;
  await app.listen({ port: 0, host: "127.0.0.1" });
  base = `http://127.0.0.1:${(app.server.address() as { port: number }).port}`;
});
afterAll(async () => {
  await app.close();
  if (AEGIS_DIR_BEFORE === undefined) delete process.env.AEGIS_DIR; else process.env.AEGIS_DIR = AEGIS_DIR_BEFORE;
  rmSync(scratchHome, { recursive: true, force: true });
});

// Fastify's in-memory inject() breaks under Bun (ERR_HTTP_HEADERS_SENT), so this goes over loopback.
async function issue(body: Record<string, unknown>) {
  const r = await fetch(`${base}/api/v1/aegis/session`, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
  });
  const json = await r.json();
  return { statusCode: r.status, json: () => json };
}

describe.skipIf(unsafe)("ASE parent lineage", () => {
  test("control: a child of a real parent is narrowed to parent & requested", async () => {
    const parent = await issue({ service_key: "lineage-test", perm_mask: 0b0011, trust_mask: 0b0011 });
    expect(parent.statusCode).toBeLessThan(300);
    const parentId = parent.json().session_id;
    expect(typeof parentId).toBe("string");

    const child = await issue({ service_key: "lineage-test", parent_session_id: parentId, perm_mask: 0b1111 });
    expect(child.statusCode).toBeLessThan(300);
    expect(child.json().perm_mask).toBe(0b0011);
  });

  // GTP-021: missing lineage is never read as a root.
  // Was a hole until 2026-10-14: the route answered 200 with perm_mask 65535 (the whole request).
  test("a child naming a parent that does not exist is refused, not given its whole request", async () => {
    const child = await issue({ service_key: "lineage-test", parent_session_id: "ses_does_not_exist", perm_mask: 0xffff });
    // On failure this shows what the child was given: { status, perm_mask }.
    expect({ status: child.statusCode, perm_mask: child.json().perm_mask }).toEqual({ status: 422, perm_mask: undefined });
  });
});
