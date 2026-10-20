// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// AGS-016 / INF-AGS-007 — authorize() accepts only the token aegis issued. Every limit authorize checks
// (mask, task_scope, human_in_loop_required, max_transaction_value, max_depth) is read from the token, so
// an agent that edits its own token must be refused, not judged by the limits it wrote itself.
// Found 2026-10-21 by the aegis-bulkhead battery. Runs under a throwaway HOME and AEGIS_DIR.

import { afterAll, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

const scratchHome = mkdtempSync(join(tmpdir(), "aegis-authz-integrity-"));
const HOME_BEFORE = process.env.HOME;
const AEGIS_DIR_BEFORE = process.env.AEGIS_DIR;
process.env.HOME = scratchHome;
process.env.AEGIS_DIR = join(scratchHome, ".aegis");

const { getDbPath } = await import("../src/core/config");
// Bun shares loaded modules across test files, and aegis fixes its home when config first loads. In a
// full-suite run another file may have loaded it under the real HOME: issuing tokens there writes into the
// live aegis.db (it did, 21 Oct 2026). Run only where the database is under the scratch HOME, or on CI.
const unsafe = !getDbPath().startsWith(scratchHome) && !process.env.CI;
if (unsafe) console.warn(`[authorize-token-integrity] SKIPPED: database resolves to ${getDbPath()}, not the scratch HOME; run this file on its own`);
const { issueSdt } = await import("../src/auth/sdt");
const { authorize } = await import("../src/auth/authorize");

afterAll(() => {
  process.env.HOME = HOME_BEFORE;
  if (AEGIS_DIR_BEFORE === undefined) delete process.env.AEGIS_DIR; else process.env.AEGIS_DIR = AEGIS_DIR_BEFORE;
  rmSync(scratchHome, { recursive: true, force: true });
});

const T = unsafe ? test.skip : test;
const root = unsafe ? ({ token: {} } as any) : issueSdt({ agent_id: "orch", agent_class: "orchestrator", spawner_id: "human:s1", requested_mask: 0b1111, task_scope: ["vessel.read", "vessel.write"] });
const child = unsafe ? ({ token: {} } as any) : issueSdt({
  agent_id: "worker", agent_class: "worker", spawner_id: "orch", parent_token_id: root.token.token_id,
  requested_mask: 0b0011, task_scope: ["vessel.read"], max_transaction_value: 100,
});
const ask = (token: unknown, resource = "vessel", action = "read", value = 0) =>
  authorize({ agent_token: token as any, resource, action, context: { value } } as any);
const edit = (t: any, f: (x: any) => void) => { const c = structuredClone(t); f(c); return c; };

describe("control: the issued token is judged by its own limits", () => {
  T("in scope: authorized", async () => {
    expect((await ask(child.token)).reason).not.toMatch(/TOKEN_/);
    expect((await ask(child.token)).authorized).toBe(true);
  });
  T("out of scope: refused by scope, as before", async () => {
    expect((await ask(child.token, "vessel", "write")).reason).toBe("OUT_OF_SCOPE");
  });
});

describe("AGS-016 — an edited token is refused before its own limits are read", () => {
  const cases: [string, (x: any) => void][] = [
    ["raised mask", (x) => { x.delegation.delegated_mask = 0b1111; }],
    ["emptied task_scope", (x) => { x.delegation.task_scope = []; }],
    ["human-in-loop switched off", (x) => { x.delegation.human_in_loop_required = false; x.delegation.max_depth = 9; }],
    ["transaction limit removed", (x) => { x.delegation.max_transaction_value = 0; }],
    ["expiry extended", (x) => { x.delegation.expiry = "2099-01-01T00:00:00Z"; }],
  ];
  for (const [name, f] of cases) {
    T(name, async () => {
      const r = await ask(edit(child.token, f), "vessel", "write", 1000);
      expect(r.authorized).toBe(false);
      expect(r.reason).toBe("TOKEN_ALTERED");
    });
  }
  T("a root token with a raised mask", async () => {
    const r = await ask(edit(root.token, (x) => { x.delegation.delegated_mask = 0xffff; }));
    expect(r.reason).toBe("TOKEN_ALTERED");
  });
  T("a token aegis never issued", async () => {
    const r = await ask(edit(child.token, (x) => { x.token_id = "00000000-0000-0000-0000-000000000000"; }));
    expect(r.reason).toBe("TOKEN_NOT_ISSUED");
  });
});
