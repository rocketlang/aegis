// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// bun src/bulkhead/cli.ts <command>   (joins the 'aegis' dispatcher in P2; INF-BLK-004)
//
//   serve                                  run the bulkhead process on <dir>/bulkhead.sock
//   send  <token.json> <message.json>      send a FINDING / REQUEST / ACK
//   read  <token.json>                     read your messages (you are tainted by each one)
//   drop  <token.json> <message_id>        drop a taint early (written in the bell book)
//   close <compartment> "<reason>"         close every door of a compartment
//   open  <door>                           re-open a tripped door
//   open-compartment <compartment>
//   status
//   verify                                 re-walk the bell book: exit 0 holds · 1 broken · 3 broke
//
// Directory: $AEGIS_BULKHEAD_DIR, else ~/.aegis/bulkhead.

import { readFileSync } from "fs";
import { join } from "path";
import { homedir } from "os";
import { verifyBellBook } from "./bell-book";
import { call } from "./server";

const dir = process.env.AEGIS_BULKHEAD_DIR || join(homedir(), ".aegis", "bulkhead");
const [cmd, a, b] = process.argv.slice(2);
const json = (p: string) => JSON.parse(readFileSync(p, "utf-8"));
const print = (x: unknown) => console.log(JSON.stringify(x, null, 2));

try {
  switch (cmd) {
    case "serve": {
      const { Bulkhead } = await import("./bulkhead");
      const { sdtIdentity } = await import("./identity");
      const { serve } = await import("./server");
      const bh = new Bulkhead({ dir, identity: await sdtIdentity(), onAlarm: (x) => process.stderr.write(`[bulkhead] ALARM ${x.rule ?? ""} ${x.text}\n`) });
      serve(bh);
      process.stderr.write(`[bulkhead] serving on ${join(dir, "bulkhead.sock")} (doors: ${bh.doorsPath})\n`);
      break;
    }
    case "send": print(await call(dir, { op: "send", token: json(a), message: json(b) })); break;
    case "read": print(await call(dir, { op: "read", token: json(a) })); break;
    case "drop": print(await call(dir, { op: "drop", token: json(a), message_id: b })); break;
    case "close": print(await call(dir, { op: "close", compartment: a, reason: b, by: process.env.USER ?? "person" })); break;
    case "open": print(await call(dir, { op: "open", door: a, by: process.env.USER ?? "person" })); break;
    case "open-compartment": print(await call(dir, { op: "open-compartment", compartment: a, by: process.env.USER ?? "person" })); break;
    case "status": print(await call(dir, { op: "status" })); break;
    case "verify": {
      const v = verifyBellBook(join(dir, "bell-book.jsonl"));
      print(v);
      process.exit(v.holds ? 0 : 1);
    }
    default:
      console.error("usage: bun src/bulkhead/cli.ts serve|send|read|drop|close|open|open-compartment|status|verify");
      process.exit(2);
  }
} catch (e) {
  console.error(`bulkhead: ${(e as Error).message}`);
  process.exit(3);
}
