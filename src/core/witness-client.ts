// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// witness-client — the governor's side of the off-box witness. Streams signed rows (refusals + a
// periodic heartbeat) to the collector. Fire-and-forget, short timeout: the witness being
// unreachable must never change a local verdict — but a witness that stops HEARING is the alarm it
// exists to raise (its own `stall`), so a dropped send is surfaced there, not swallowed silently.

import { request } from "http";
import type { SignedRow } from "./ledger-sign";

/** POST one signed row to the witness for a source. Resolves ok|false; never throws. */
export function sendToWitness(baseUrl: string, source: string, row: SignedRow, timeoutMs = 3000): Promise<boolean> {
  return new Promise((resolve) => {
    let done = false;
    const fin = (ok: boolean) => { if (!done) { done = true; resolve(ok); } };
    try {
      const u = new URL(`/ingest/${encodeURIComponent(source)}`, baseUrl);
      const body = Buffer.from(JSON.stringify(row), "utf8");
      const req = request(
        { hostname: u.hostname, port: u.port, path: u.pathname, method: "POST",
          headers: { "content-type": "application/json", "content-length": body.length } },
        (res) => { res.resume(); fin((res.statusCode ?? 500) < 300); },
      );
      req.setTimeout(timeoutMs, () => { try { req.destroy(); } catch { /* */ } fin(false); });
      req.on("error", () => fin(false));
      req.write(body); req.end();
    } catch { fin(false); }
  });
}
