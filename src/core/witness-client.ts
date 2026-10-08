// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// witness-client — the authority's side of the off-box witness. Sends signed rows and a periodic
// signed heartbeat to the collector. Short timeout, never throws: the witness being unreachable
// must never change a local verdict. A send that fails is not trusted to report itself — the
// heartbeat carries the authority's last seq, so a row that never arrived shows at the witness as
// a gap, and an authority that stops sending shows as its `stall`.

import { request } from "http";
import { request as requestTls } from "https";
import type { SignedRow, Heartbeat } from "./ledger-sign";

interface Reply { status: number; body: string }

function call(method: "GET" | "POST", baseUrl: string, path: string, payload: unknown, timeoutMs: number): Promise<Reply | null> {
  return new Promise((resolve) => {
    let done = false;
    const fin = (r: Reply | null) => { if (!done) { done = true; resolve(r); } };
    try {
      const u = new URL(path, baseUrl);
      const body = payload === undefined ? null : Buffer.from(JSON.stringify(payload), "utf8");
      const req = (u.protocol === "https:" ? requestTls : request)(
        { hostname: u.hostname, port: u.port, path: u.pathname, method,
          headers: body ? { "content-type": "application/json", "content-length": body.length } : {} },
        (res) => {
          let text = "";
          res.setEncoding("utf8");
          res.on("data", (d) => { if (text.length < 100_000) text += d; });
          res.on("end", () => fin({ status: res.statusCode ?? 500, body: text }));
        },
      );
      req.setTimeout(timeoutMs, () => { try { req.destroy(); } catch { /* */ } fin(null); });
      req.on("error", () => fin(null));
      if (body) req.write(body);
      req.end();
    } catch { fin(null); }
  });
}

/** POST one signed row to the witness for a source. Resolves ok|false; never throws. */
export async function sendToWitness(baseUrl: string, source: string, row: SignedRow, timeoutMs = 3000): Promise<boolean> {
  const r = await call("POST", baseUrl, `/ingest/${encodeURIComponent(source)}`, row, timeoutMs);
  return !!r && r.status < 300;
}

/** POST a signed heartbeat. Resolves true when the witness received it (even if it alarmed). */
export async function sendHeartbeat(baseUrl: string, source: string, hb: Heartbeat, timeoutMs = 3000): Promise<boolean> {
  const r = await call("POST", baseUrl, `/heartbeat/${encodeURIComponent(source)}`, hb, timeoutMs);
  return !!r && (r.status < 300 || r.status === 409);
}

/** The last seq the witness holds for a source, or null when it cannot be asked. */
export async function witnessHighWaterMark(baseUrl: string, source: string, timeoutMs = 3000): Promise<number | null> {
  const r = await call("GET", baseUrl, `/hwm/${encodeURIComponent(source)}`, undefined, timeoutMs);
  if (!r || r.status >= 300) return null;
  try {
    const n = (JSON.parse(r.body) as { maxSeq?: unknown }).maxSeq;
    return typeof n === "number" ? n : null;
  } catch { return null; }
}
