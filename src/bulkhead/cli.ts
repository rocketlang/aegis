// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// aegis bulkhead <command>   (also: bun src/bulkhead/cli.ts <command>)
//
//   serve                                  run the bulkhead process on <dir>/bulkhead.sock
//   send  <token.json> <message.json>      send a FINDING / REQUEST / ACK
//   read  <token.json>                     read your messages (you are tainted by each one)
//   drop  <token.json> <message_id>        drop a taint early (written in the bell book)
//   close <compartment> "<reason>"         close every door of a compartment (anyone may close)
//   open  <door-or-compartment>            a PERSON re-opens it: raises its open epoch in doors.json (BLK-012)
//   status
//   verify                                 re-walk the bell book: exit 0 holds · 1 broken · 3 broke
//
// Directory: $AEGIS_BULKHEAD_DIR, else <aegis dir>/bulkhead (~/.aegis/bulkhead).

import { readFileSync } from "fs";
import { join } from "path";
import { getAegisDir } from "../core/config";
import { verifyBellBook } from "./bell-book";
import { raiseOpenEpoch } from "./doors";
import { call } from "./server";

export function bulkheadDir(): string {
  return process.env.AEGIS_BULKHEAD_DIR || join(getAegisDir(), "bulkhead");
}

export async function main(argv: string[]): Promise<void> {
  const dir = bulkheadDir();
  const [cmd, a, b] = argv;
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
        return;
      }
      case "send": return print(await call(dir, { op: "send", token: json(a), message: json(b) }));
      case "read": return print(await call(dir, { op: "read", token: json(a) }));
      case "drop": return print(await call(dir, { op: "drop", token: json(a), message_id: b }));
      case "close": return print(await call(dir, { op: "close", compartment: a, reason: b, by: process.env.USER ?? "unknown" }));
      case "open": {
        if (!a) { console.error("usage: aegis bulkhead open <door-or-compartment>"); process.exit(2); }
        const epoch = raiseOpenEpoch(join(dir, "doors.json"), a);
        return print({ ok: true, id: a, open_epoch: epoch, note: "takes effect on the bulkhead's next decision" });
      }
      case "status": return print(await call(dir, { op: "status" }));
      case "verify": {
        const v = verifyBellBook(join(dir, "bell-book.jsonl"));
        print(v);
        process.exit(v.holds ? 0 : 1);
      }
      default:
        console.error("usage: aegis bulkhead serve|send|read|drop|close|open|status|verify");
        process.exit(2);
    }
  } catch (e) {
    console.error(`bulkhead: ${(e as Error).message}`);
    process.exit(3);
  }
}

if (import.meta.main) await main(process.argv.slice(2));
