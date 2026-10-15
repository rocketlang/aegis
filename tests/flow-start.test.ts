// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// Gap 1 of the flow guardrails (GTP-017/019/022): at a session start each session gets its own mandate and
// its own root envelope naming it. The real ASE route runs in-process; a throwaway HOME holds everything.

import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { spawnSync } from "child_process";

const home = mkdtempSync(join(tmpdir(), "aegis-flow-start-"));
process.env.HOME = home;
process.env.AEGIS_DIR = join(home, ".aegis");
process.env.KAVACHOS_MUDRIKA_SECRET = "t";
const approvers = join(home, "approvers.json");
writeFileSync(approvers, JSON.stringify({ owners: { telegram: ["555000111"] } }));
process.env.AOS_APPROVERS_FILE = approvers;
mkdirSync(join(home, ".aegis"), { recursive: true });

const { default: Fastify } = await import("fastify");
const { registerAseRoutes } = await import("../src/dashboard/routes/ase");
const { getAegisDir } = await import("../src/core/config");
const M = await import("../src/kavach/mandate");
const { startFlow, readFlowRoot } = await import("../src/kavach/flow-start");

const unsafe = !getAegisDir().startsWith(home) && !process.env.CI;
if (unsafe) console.warn(`[flow-start] SKIPPED: aegis dir resolves to ${getAegisDir()}; run this file on its own`);

// The config module fixes its directory at first load: write the config where the route reads it.
const configPath = join(getAegisDir(), "config.json");
const configBefore = existsSync(configPath) ? readFileSync(configPath, "utf8") : null;
const mode = (m: "enforce" | "monitor") => writeFileSync(configPath, JSON.stringify({
  enforcement: { mode: m === "enforce" ? "enforce" : "monitor" },
  kavach: m === "enforce" ? { enabled: true, mandate: "enforce" } : { enabled: true },
}));

const app = Fastify();
registerAseRoutes(app);
let base = "";
const sent: Array<Record<string, unknown>> = [];
const spy: typeof fetch = async (url, init) => {
  sent.push(JSON.parse(String(init?.body ?? "{}")));
  return fetch(url, init);
};
const deps = () => ({ aegisUrl: base, fetchFn: spy, remoteOf: () => null });

beforeAll(async () => {
  if (unsafe) return;
  mode("monitor");
  await app.listen({ port: 0, host: "127.0.0.1" });
  base = `http://127.0.0.1:${(app.server.address() as { port: number }).port}`;
});
afterAll(async () => {
  await app.close();
  if (!unsafe) { if (configBefore === null) rmSync(configPath, { force: true }); else writeFileSync(configPath, configBefore); }
  rmSync(home, { recursive: true, force: true });
});

describe.skipIf(unsafe)("aegis flow-start (SessionStart)", () => {
  test("a new session: a mandate is issued, and the root envelope is requested naming it", async () => {
    sent.length = 0;
    const r = await startFlow({ session_id: "fs-1", cwd: "/tmp" }, deps());
    expect(r.root?.mandate_status).toBe("valid");
    expect(r.root?.mandate_id).toMatch(/^mdr_/);
    expect(sent).toHaveLength(1);
    expect(sent[0].mandate_id).toBe(r.root?.mandate_id);
    expect(r.root?.envelope_session_id).toMatch(/\S/);
    expect(readFlowRoot("fs-1")?.envelope_session_id).toBe(r.root!.envelope_session_id);
  });

  test("a resume with a valid mandate keeps the mandate and the envelope, and asks for nothing", async () => {
    const first = readFlowRoot("fs-1")!;
    sent.length = 0;
    const r = await startFlow({ session_id: "fs-1", cwd: "/tmp", source: "resume" }, deps());
    expect(sent).toHaveLength(0);
    expect(r.root?.mandate_id).toBe(first.mandate_id);
    expect(r.root?.envelope_session_id).toBe(first.envelope_session_id);
  });

  test("an expired mandate is renewed at session start, with a new envelope naming the new one", async () => {
    M.issueMandate("fs-2", { trustMask: 1, scopeKey: "x", principal: "owner:t", now: new Date(Date.now() - 25 * 3600 * 1000) });
    const old = M.loadMandateForSession("fs-2")!;
    sent.length = 0;
    const r = await startFlow({ session_id: "fs-2", cwd: "/tmp" }, deps());
    expect(r.note).toContain(`was ${old.mudrika_id}, expired`);
    expect(r.root?.mandate_id).not.toBe(old.mudrika_id);
    expect(sent[0].mandate_id).toBe(r.root?.mandate_id);
  });

  test("a revoked mandate is NOT replaced, and the session gets no live root envelope (GTP-022)", async () => {
    await startFlow({ session_id: "fs-3", cwd: "/tmp" }, deps());
    const m = M.loadMandateForSession("fs-3")!;
    M.revokeMandate(m.mudrika_id, "test");
    sent.length = 0;
    const r = await startFlow({ session_id: "fs-3", cwd: "/tmp", source: "resume" }, deps());
    expect(sent).toHaveLength(0);
    expect(r.root?.mandate_id).toBe(m.mudrika_id);
    expect(r.root?.mandate_status).toBe("revoked");
    expect(r.root?.envelope_session_id).toBeNull();
  });

  test("no principal: no mandate, nothing requested", async () => {
    const was = process.env.AOS_APPROVERS_FILE;
    process.env.AOS_APPROVERS_FILE = join(home, "nobody.json");
    sent.length = 0;
    const r = await startFlow({ session_id: "fs-4", cwd: "/tmp" }, deps());
    process.env.AOS_APPROVERS_FILE = was;
    expect(r.root?.mandate_status).toBe("missing");
    expect(sent).toHaveLength(0);
  });

  test("Aegis unreachable: the mandate is still issued, the envelope is recorded as not issued, nothing throws", async () => {
    const r = await startFlow({ session_id: "fs-5", cwd: "/tmp" }, { aegisUrl: "http://127.0.0.1:9", remoteOf: () => null });
    expect(r.root?.mandate_status).toBe("valid");
    expect(r.root?.envelope_session_id).toBeNull();
    expect(r.note).toContain("unreachable");
  });

  test("enforce, opted in: the root envelope is issued and capped by the mandate's mask", async () => {
    mode("enforce");
    const r = await startFlow({ session_id: "fs-6", cwd: "/tmp" }, deps());
    mode("monitor");
    expect(r.root?.envelope_session_id).toMatch(/\S/);
    const env = await (await fetch(`${base}/api/v1/aegis/session/${encodeURIComponent(r.root!.envelope_session_id!)}`)).json() as { perm_mask?: number };
    const mandate = M.loadMandateById(r.root!.mandate_id!)!;
    expect(typeof env.perm_mask).toBe("number");
    expect(((env.perm_mask as number) & ~mandate.trust_mask) >>> 0).toBe(0);
  });

  test("a child session (AEGIS_FLOW) gets its envelope as a child of its parent's, narrowed by it", async () => {
    const parent = await startFlow({ session_id: "fs-p", cwd: "/tmp" }, deps());
    sent.length = 0;
    const child = await startFlow({ session_id: "fs-c", cwd: "/tmp" }, { ...deps(), flowEnv: `fs-p:${parent.root!.mandate_id}` });
    expect(child.root?.parent_session).toBe("fs-p");
    expect(sent).toHaveLength(1);
    expect(sent[0].parent_session_id).toBe(parent.root!.envelope_session_id);
    expect(sent[0].mandate_id).toBeUndefined();
    const p = await (await fetch(`${base}/api/v1/aegis/session/${encodeURIComponent(parent.root!.envelope_session_id!)}`)).json() as { perm_mask: number };
    const c = await (await fetch(`${base}/api/v1/aegis/session/${encodeURIComponent(child.root!.envelope_session_id!)}`)).json() as { perm_mask: number };
    expect(typeof c.perm_mask).toBe("number");
    expect((c.perm_mask & ~p.perm_mask) >>> 0).toBe(0);
  });

  test("a child whose parent has no root envelope is not made a root", async () => {
    const parent = await startFlow({ session_id: "fs-p2", cwd: "/tmp" }, { aegisUrl: "http://127.0.0.1:9", remoteOf: () => null });
    expect(parent.root?.envelope_session_id).toBeNull();
    sent.length = 0;
    const child = await startFlow({ session_id: "fs-c2", cwd: "/tmp" }, { ...deps(), flowEnv: `fs-p2:${parent.root!.mandate_id}` });
    expect(sent).toHaveLength(0);
    expect(child.root?.envelope_session_id).toBeNull();
    expect(child.note).toContain("parent flow has no root envelope");
  });

  test("the hook itself never stops a session and prints nothing on stdout", () => {
    const h = mkdtempSync(join(home, "cli-"));
    const r = spawnSync("bun", ["run", join(import.meta.dir, "..", "src/cli/index.ts"), "flow-start"], {
      input: "not json", encoding: "utf8", timeout: 30000,
      env: { ...(process.env as Record<string, string>), HOME: h, AEGIS_DIR: join(h, ".aegis"), AEGIS_URL: "http://127.0.0.1:9" },
    });
    expect(r.status).toBe(0);
    expect(r.stdout).toBe("");
    expect(r.stderr).toContain("[flow-start]");
  });
});
