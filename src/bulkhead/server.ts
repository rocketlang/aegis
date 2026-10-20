// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// The bulkhead process: one owner of the bell book and the state, on a unix socket (no TCP port).
// One JSON request per line, one JSON answer per line.
// @rule:BLK-005 the bell book is written by this process, never by an agent
// @rule:INF-BLK-004 Phase 1: touches no live gate, no signed ledger, no systemd unit

import { createServer, type Server, type Socket } from "net";
import { chmodSync, existsSync, unlinkSync } from "fs";
import { join } from "path";
import type { Bulkhead } from "./bulkhead";

export function socketPath(dir: string): string { return join(dir, "bulkhead.sock"); }

export function handle(b: Bulkhead, req: any): unknown {
  switch (req?.op) {
    case "send": return b.send(req.token, req.message ?? {});
    case "read": return b.read(req.token);
    case "drop": return b.dropTaint(req.token, String(req.message_id ?? ""));
    case "authority": return b.authority(String(req.agent_id ?? ""), Number(req.own_mask ?? 0));
    case "alarm": b.alarm(String(req.from ?? "unknown"), String(req.text ?? "")); return { ok: true };
    // Person controls. In P1 anyone who can reach the socket can call these; P2 limits them to a person.
    case "close": b.closeCompartment(String(req.compartment), String(req.by ?? "person"), String(req.reason ?? "closed by hand")); return { ok: true };
    case "open-compartment": return { ok: b.openCompartment(String(req.compartment), String(req.by ?? "person")) };
    case "open": return { ok: b.openDoor(String(req.door), String(req.by ?? "person")) };
    case "status": return b.status();
    default: return { error: `unknown op ${req?.op}` };
  }
}

export function serve(b: Bulkhead): Server {
  const path = socketPath(b.dir);
  if (existsSync(path)) unlinkSync(path);
  const server = createServer((sock: Socket) => {
    let buf = "";
    sock.on("data", (d) => {
      buf += d.toString();
      let i: number;
      while ((i = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i + 1);
        let out: unknown;
        try { out = handle(b, JSON.parse(line)); } catch (e) { out = { error: (e as Error).message }; }
        sock.write(JSON.stringify(out) + "\n");
      }
    });
    sock.on("error", () => {});
  });
  server.listen(path, () => { try { chmodSync(path, 0o600); } catch {} });
  return server;
}

export function call(dir: string, req: unknown): Promise<any> {
  return new Promise((resolve, reject) => {
    const { connect } = require("net") as typeof import("net");
    const s = connect(socketPath(dir));
    let buf = "";
    s.on("connect", () => s.write(JSON.stringify(req) + "\n"));
    s.on("data", (d) => { buf += d.toString(); const i = buf.indexOf("\n"); if (i >= 0) { s.end(); resolve(JSON.parse(buf.slice(0, i))); } });
    s.on("error", reject);
  });
}
