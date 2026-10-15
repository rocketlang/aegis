// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// checkTurn, steps 0–9, and the P4 exit criterion (governed-turn-protocol §19): the same envelope is
// accepted over HTTP and through a hook, and the same tampered envelope is refused by both.

import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { checkTurn, envelopeFromHeaders, envelopeFromJson, signEnvelope, type Fields, type LocalEnvelope, type Substrate } from "../src/index";

const M = (...bits: number[]) => bits.reduce((m, b) => m | (1 << b), 0);
const OPERATOR = M(8, 9, 12, 19);
const VIEWER = M(12);
const pair = () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return { pub: publicKey.export({ type: "spki", format: "pem" }).toString(), priv: privateKey.export({ type: "pkcs8", format: "pem" }).toString() };
};
const agentKey = pair();
const humanKey = pair();
const catalog = {
  "loadboard.read": { bit: 12, verb: "can_read", reversibility: "reversible" },
  "bid.place": { bit: 8, verb: "can_act", reversibility: "reversible" },
  "ebl.transfer": { bit: 19, verb: "can_act", reversibility: "irreversible" },
};
const NOW = 1_781_430_000_000;
const substrate = (over: Partial<Substrate> = {}): Substrate => ({
  keyRegistry: {
    "ed25519:agent": { publicKey: agentKey.pub, driverId: "aos", driverType: "agent" },
    "ed25519:desk": { publicKey: humanKey.pub, driverId: "desk@fr8x", driverType: "human" },
  },
  sessions: {
    agent_viewer: { sessionMask: OPERATOR, sealedBudgetLeft: 50, trustByDriver: { aos: VIEWER } },
    human_desk: { sessionMask: OPERATOR, sealedBudgetLeft: 50, trustByDriver: { "desk@fr8x": OPERATOR } },
  },
  catalog, level: "L1", now: NOW, seenNonces: new Map(),
  ...over,
});

let seq = 0;
function envelope(o: { type?: string; id?: string; keyid?: string; priv?: string; slug?: string; verb?: string; bit?: number; cred?: string; commit?: string; created?: number; nonce?: string } = {}): LocalEnvelope {
  const keyid = o.keyid ?? "ed25519:agent";
  const fields: Fields = {
    "gtp-version": "0.4",
    "gtp-turn": `id="t_${++seq}"`,
    "gtp-driver": `type=${o.type ?? "agent"}; id="${o.id ?? "aos"}"; keyid="${keyid}"`,
    "gtp-session": `cred="${o.cred ?? "agent_viewer"}"`,
    "gtp-capability": `service=fr8x; slug="${o.slug ?? "loadboard.read"}"; verb=${o.verb ?? "can_read"}; bit=${o.bit ?? 12}`,
    "gtp-commit": `mode=${o.commit ?? "auto"}`,
    ...(o.verb === "can_act" ? { "gtp-intent": `present=true; digest="d"` } : {}),
  };
  const signed = signEnvelope({ method: "POST", path: "/api/turn", headers: fields, privateKeyPem: o.priv ?? agentKey.priv, keyid, created: o.created ?? NOW / 1000, nonce: o.nonce ?? `n_${seq}` });
  return { method: "POST", path: "/api/turn", fields: signed };
}

describe("checkTurn", () => {
  test("a signed read inside the masks passes", async () => {
    const r = await checkTurn(envelope(), substrate());
    expect(r.verdict.status).toBe("PASS");
    expect(r.enforced).toBe(true);
  });

  test("no envelope → 428 (GTP-INV-3)", async () => {
    const r = await checkTurn({ method: "GET", path: "/", fields: {} }, substrate());
    expect([r.verdict.httpCode, r.verdict.rule]).toEqual([428, "GTP-INV-3"]);
  });

  test("a field changed after signing → 401", async () => {
    const e = envelope();
    e.fields["gtp-capability"] = `service=fr8x; slug="ebl.transfer"; verb=can_act; bit=19`;
    expect((await checkTurn(e, substrate())).verdict.code).toBe("GTP_UNIDENTIFIED");
  });

  test("an unknown key → 401", async () => {
    const e = envelope({ keyid: "ed25519:nobody" });
    expect((await checkTurn(e, substrate())).verdict.detail).toContain("unknown keyid");
  });

  test("a key claiming another driver → 401: the agent's key cannot sign as the human desk (GTP-011)", async () => {
    const e = envelope({ type: "human", id: "desk@fr8x", keyid: "ed25519:agent", cred: "human_desk", slug: "ebl.transfer", verb: "can_act", bit: 19, commit: "pause" });
    const r = await checkTurn(e, substrate());
    expect(r.verdict.httpCode).toBe(401);
    expect(r.verdict.detail).toContain("registered to agent:aos");
  });

  test("a key registered to no driver identifies nobody → 401", async () => {
    const sub = substrate();
    (sub.keyRegistry["ed25519:agent"] as { driverId?: string }).driverId = undefined;
    expect((await checkTurn(envelope(), sub)).verdict.httpCode).toBe(401);
  });

  test("the same nonce twice → the second is 401", async () => {
    const sub = substrate();
    expect((await checkTurn(envelope({ nonce: "same" }), sub)).verdict.status).toBe("PASS");
    expect((await checkTurn(envelope({ nonce: "same" }), sub)).verdict.detail).toBe("replayed nonce");
  });

  test("created outside the 300 s window, either way → 401 (GTP-YK-003)", async () => {
    expect((await checkTurn(envelope({ created: NOW / 1000 - 301 }), substrate())).verdict.httpCode).toBe(401);
    expect((await checkTurn(envelope({ created: NOW / 1000 + 301 }), substrate())).verdict.httpCode).toBe(401);
    expect((await checkTurn(envelope({ created: NOW / 1000 - 299 }), substrate())).verdict.status).toBe("PASS");
  });

  test("an unknown session → 401, never a default session", async () => {
    expect((await checkTurn(envelope({ cred: "ghost" }), substrate())).verdict.detail).toContain("unknown session");
  });

  test("sessions may be looked up asynchronously", async () => {
    const sub = substrate({ sessions: async (cred: string) => (cred === "agent_viewer" ? { sessionMask: OPERATOR, trustByDriver: { aos: VIEWER } } : null) });
    expect((await checkTurn(envelope(), sub)).verdict.status).toBe("PASS");
  });

  test("the agent without the money bit is refused by mask (GTP-INV-6); the human desk is held (423)", async () => {
    const agent = await checkTurn(envelope({ slug: "ebl.transfer", verb: "can_act", bit: 19, commit: "pause" }), substrate());
    expect(agent.verdict.rule).toBe("GTP-INV-6");
    const desk = await checkTurn(envelope({ type: "human", id: "desk@fr8x", keyid: "ed25519:desk", priv: humanKey.priv, cred: "human_desk", slug: "ebl.transfer", verb: "can_act", bit: 19 }), substrate());
    expect([desk.verdict.status, desk.verdict.httpCode]).toEqual(["PAUSED", 423]);
  });

  test("L0 gives the same verdict and says it does not enforce", async () => {
    const r = await checkTurn(envelope({ slug: "ebl.transfer", verb: "can_act", bit: 19, commit: "pause" }), substrate({ level: "L0" }));
    expect(r.verdict.status).toBe("REFUSED");
    expect(r.enforced).toBe(false);
  });

  test("signEnvelope signs now with a fresh nonce when none is given (0.1.1)", async () => {
    const fields: Fields = { "gtp-version": "0.4", "gtp-driver": `type=agent; id="aos"; keyid="ed25519:agent"`, "gtp-session": `cred="agent_viewer"`, "gtp-capability": `service=fr8x; slug="loadboard.read"; verb=can_read; bit=12` };
    const a = signEnvelope({ method: "POST", path: "/api/turn", headers: fields, privateKeyPem: agentKey.priv, keyid: "ed25519:agent" });
    const b = signEnvelope({ method: "POST", path: "/api/turn", headers: fields, privateKeyPem: agentKey.priv, keyid: "ed25519:agent" });
    expect(a["signature-input"]).not.toBe(b["signature-input"]);
    const sub = substrate({ now: undefined });
    expect((await checkTurn({ method: "POST", path: "/api/turn", fields: a }, sub)).verdict.status).toBe("PASS");
    expect((await checkTurn({ method: "POST", path: "/api/turn", fields: b }, sub)).verdict.status).toBe("PASS");
  });

  test("envelopeFromJson refuses what is not an envelope", () => {
    expect(envelopeFromJson(null)).toBeNull();
    expect(envelopeFromJson({ method: "POST", path: "/x" })).toBeNull();
    expect(envelopeFromJson({ method: "POST", path: "/x", fields: [] })).toBeNull();
  });
});

// ── P4 exit: one envelope, two positions ─────────────────────────────────────────────────────────

const dir = mkdtempSync(join(tmpdir(), "gtp-verify-"));
// The shipped command (dist/cli.js, under plain Node) when it is built, as in the release workflow, which
// builds first; otherwise the same source under Bun, as in the repository's own CI, which does not.
const built = join(import.meta.dir, "..", "dist", "cli.js");
const cli = existsSync(built) ? ["node", built] : ["bun", join(import.meta.dir, "..", "src", "cli.ts")];
let server: Server;
let url = "";
// The HTTP position: a gate that reads the envelope from headers and answers with the verdict's code.
beforeAll(async () => {
  const sub = substrate({ now: undefined });
  server = createServer(async (req, res) => {
    const r = await checkTurn(envelopeFromHeaders(req.method ?? "", req.url ?? "", req.headers as Record<string, string>), sub);
    res.writeHead(r.verdict.httpCode, { "content-type": "application/json" }).end(JSON.stringify(r.verdict));
  });
  await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
  url = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
});
afterAll(() => { server?.close(); rmSync(dir, { recursive: true, force: true }); });

function hook(env: LocalEnvelope, nonces?: string): { code: number | null; out: string } {
  const s = substrate();
  const file = join(dir, "substrate.json");
  writeFileSync(file, JSON.stringify({ keyRegistry: s.keyRegistry, sessions: s.sessions, catalog: s.catalog, level: "L1" }));
  const r = spawnSync(cli[0], cli.slice(1), { input: JSON.stringify({ gtp: env }), env: { ...process.env, GTP_SUBSTRATE: file, ...(nonces ? { GTP_NONCES: nonces } : {}) }, encoding: "utf8" });
  return { code: r.status, out: r.stdout };
}
const live = (o: Parameters<typeof envelope>[0] = {}) => envelope({ created: Math.floor(Date.now() / 1000), ...o });

describe("one envelope, two positions (P4 exit)", () => {
  test("the same signed envelope is accepted over HTTP and through the hook", async () => {
    const e = live();
    const http = await fetch(`${url}${e.path}`, { method: e.method, headers: e.fields as Record<string, string> });
    expect(http.status).toBe(200);
    const h = hook(e);
    expect(h.code).toBe(0);
    expect(JSON.parse(h.out).verdict.status).toBe("PASS");
  });

  test("the same tampered envelope is refused by both", async () => {
    const e = live();
    e.fields["gtp-capability"] = `service=fr8x; slug="bid.place"; verb=can_act; bit=8`;
    expect((await fetch(`${url}${e.path}`, { method: e.method, headers: e.fields as Record<string, string> })).status).toBe(401);
    expect(hook(e).code).toBe(2);
  });

  test("the hook remembers nonces between runs when GTP_NONCES is set", () => {
    const e = live();
    const nonces = join(dir, "nonces.json");
    expect(hook(e, nonces).code).toBe(0);
    const again = hook(e, nonces);
    expect(again.code).toBe(2);
    expect(JSON.parse(again.out).verdict.detail).toBe("replayed nonce");
  });

  test("the hook says it could not check (3) without a substrate", () => {
    const r = spawnSync(cli[0], cli.slice(1), { input: "{}", env: { ...process.env, GTP_SUBSTRATE: "" }, encoding: "utf8" });
    expect(r.status).toBe(3);
  });
});
