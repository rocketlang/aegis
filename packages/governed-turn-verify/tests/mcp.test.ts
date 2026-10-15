// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// GTP-004: the signature covers the envelope AND the body digest. And GTP §19.4: over MCP the envelope is
// carried in the request's _meta, bound to the tool it was signed for and to its arguments.

import { describe, expect, test } from "bun:test";
import { generateKeyPairSync } from "node:crypto";
import * as V from "../src/index";

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const pub = publicKey.export({ type: "spki", format: "pem" }).toString();
const priv = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
const substrate = (): V.Substrate => ({
  keyRegistry: { "ed25519:agent": { publicKey: pub, driverId: "aos", driverType: "agent" } },
  sessions: { s1: { sessionMask: 0b1111, trustByDriver: { aos: 0b1111 } } },
  catalog: { "vessel.read": { bit: 1, verb: "can_read", reversibility: "reversible" }, "ebl.transfer": { bit: 3, verb: "can_act", reversibility: "irreversible" } },
  level: "L1", seenNonces: new Map(),
});
const fields = (slug = "vessel.read", verb = "can_read", bit = 1): V.Fields => ({
  "gtp-version": "0.4",
  "gtp-driver": `type=agent; id="aos"; keyid="ed25519:agent"`,
  "gtp-session": `cred="s1"`,
  "gtp-capability": `service=mari8x; slug="${slug}"; verb=${verb}; bit=${bit}`,
});

describe("GTP-004: the body is covered by the signature", () => {
  test("a body changed after signing is refused when the checker is given the body", async () => {
    const signed = V.signEnvelope({ method: "POST", path: "/api/turn", headers: fields(), privateKeyPem: priv, keyid: "ed25519:agent", body: { imo: "9000001" } } as never);
    const env = { method: "POST", path: "/api/turn", fields: signed };
    const ok = await V.checkTurn(env, substrate(), { body: { imo: "9000001" } } as never);
    expect(ok.verdict.status).toBe("PASS");
    const swapped = await V.checkTurn({ ...env, fields: { ...signed } }, substrate(), { body: { imo: "9999999" } } as never);
    expect(swapped.verdict.status).toBe("REFUSED");
    expect(swapped.verdict.rule).toBe("GTP-004");
  });

  test("a checker given a body refuses an envelope that does not cover one", async () => {
    const signed = V.signEnvelope({ method: "POST", path: "/api/turn", headers: fields(), privateKeyPem: priv, keyid: "ed25519:agent" });
    const r = await V.checkTurn({ method: "POST", path: "/api/turn", fields: signed }, substrate(), { body: { imo: "9000001" } } as never);
    expect(r.verdict.status).toBe("REFUSED");
    expect(r.verdict.rule).toBe("GTP-004");
  });
});

describe("MCP carriage (GTP §19.4): the envelope in _meta, bound to the tool and its arguments", () => {
  const call = (name = "vessel.read", args: Record<string, unknown> = { imo: "9000001" }) =>
    (V as any).signMcpCall({ name, arguments: args, fields: fields(), privateKeyPem: priv, keyid: "ed25519:agent" });

  test("a signed tools/call passes, and its envelope sits in params._meta", async () => {
    const params = call();
    expect(params._meta?.["io.xshieldai/gtp"]?.fields?.signature).toMatch(/\S/);
    expect((await (V as any).checkMcpCall(params, substrate())).verdict.status).toBe("PASS");
  });

  test("the same envelope with other arguments is refused", async () => {
    const params = call();
    const r = await (V as any).checkMcpCall({ ...params, arguments: { imo: "9999999" } }, substrate());
    expect(r.verdict.status).toBe("REFUSED");
    expect(r.verdict.rule).toBe("GTP-004");
  });

  test("an envelope signed for one tool is refused on another", async () => {
    const params = call();
    const r = await (V as any).checkMcpCall({ ...params, name: "ebl.transfer" }, substrate());
    expect(r.verdict.status).toBe("REFUSED");
  });

  test("a call with no envelope is 428 at L1, and passes through as a record at L0", async () => {
    const bare = { name: "vessel.read", arguments: {} };
    const r1 = await (V as any).checkMcpCall(bare, substrate());
    expect(r1.verdict.httpCode).toBe(428);
    expect(r1.enforced).toBe(true);
    const r0 = await (V as any).checkMcpCall(bare, { ...substrate(), level: "L0" });
    expect(r0.enforced).toBe(false);
  });

  test("the tool named in the call must be the capability the envelope claims", async () => {
    // signed for tool vessel.read but claiming the ebl.transfer capability
    const params = (V as any).signMcpCall({ name: "vessel.read", arguments: {}, fields: fields("ebl.transfer", "can_act", 3), privateKeyPem: priv, keyid: "ed25519:agent" });
    const r = await (V as any).checkMcpCall(params, substrate());
    expect(r.verdict.status).toBe("REFUSED");
    expect(r.verdict.rule).toBe("GTP-004");
  });
});
