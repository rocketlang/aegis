// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// aegis witness — run the off-box collector (concealment rung 3). It MUST run in a trust domain the
// agent can't write as (a different host/account). It receives signed, sequenced rows, keeps its own
// append-only copy + per-source high-water-mark, and ALARMS on gap / chain / signature / stall /
// truncation. It holds only the authority PUBLIC key — it can verify, never forge.
//
//   POST /ingest/<source>   body = one signed row (JSON)         → ingests; 202, or 409 + the alarm
//   GET  /hwm/<source>                                           → { source, maxSeq }  (for reconcile)
//   GET  /health                                                 → { status, sources }
//
// Alarms are written to the witness store dir (witness-alarms.jsonl) and stderr; a stall sweep runs
// on the heartbeat interval. Env: PORT (or AEGIS_WITNESS_PORT), AEGIS_LEDGER_PUBKEY_FILE,
// AEGIS_WITNESS_STORE (default ~/.aegis/witness), AEGIS_WITNESS_HEARTBEAT_MS (default 60000).

import { createServer } from "http";
import { existsSync, readFileSync, appendFileSync, mkdirSync } from "fs";
import { homedir } from "os";
import { join } from "path";
import { Witness, type Alarm } from "../../core/witness";
import type { SignedRow } from "../../core/ledger-sign";

export default async function witness(args: string[]): Promise<void> {
  const flag = (n: string) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : undefined; };
  const port = parseInt(flag("--port") || process.env.AEGIS_WITNESS_PORT || process.env.PORT || "4870", 10);
  const store = flag("--store") || process.env.AEGIS_WITNESS_STORE || join(process.env.AEGIS_HOME || join(homedir(), ".aegis"), "witness");
  const heartbeatMs = parseInt(process.env.AEGIS_WITNESS_HEARTBEAT_MS || "60000", 10);
  const pubFile = process.env.AEGIS_LEDGER_PUBKEY_FILE || join(process.env.AEGIS_HOME || join(homedir(), ".aegis"), "ledger-signing.pub");
  if (!existsSync(pubFile)) {
    process.stderr.write(`[aegis:witness] refusing to start — no authority public key at ${pubFile} (AEGIS_LEDGER_PUBKEY_FILE). A witness that cannot verify is not a witness.\n`);
    process.exit(3);
  }
  const pub = readFileSync(pubFile, "utf-8");
  mkdirSync(store, { recursive: true });
  const w = new Witness(pub, heartbeatMs);

  const raise = (a: Alarm) => {
    const line = JSON.stringify({ ts: new Date().toISOString(), ...a });
    try { appendFileSync(join(store, "witness-alarms.jsonl"), line + "\n"); } catch { /* best effort */ }
    process.stderr.write(`[aegis:witness] ALARM ${a.kind.toUpperCase()} source=${a.source} seq=${a.seq ?? "?"} — ${a.detail}\n`);
  };

  const srv = createServer((req, res) => {
    const url = req.url || "";
    if (req.method === "GET" && url === "/health") {
      return res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ status: "ok", sources: w.knownSources() }));
    }
    const hwm = url.match(/^\/hwm\/(.+)$/);
    if (req.method === "GET" && hwm) {
      const source = decodeURIComponent(hwm[1]);
      return res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ source, maxSeq: w.highWaterMark(source) }));
    }
    const ing = url.match(/^\/ingest\/(.+)$/);
    if (req.method === "POST" && ing) {
      const source = decodeURIComponent(ing[1]);
      let body = "";
      req.on("data", (d) => { body += d; if (body.length > 1_000_000) req.destroy(); });
      req.on("end", () => {
        let row: SignedRow;
        try { row = JSON.parse(body); } catch { return res.writeHead(400).end('{"error":"bad json"}'); }
        const alarm = w.ingest(source, row);
        if (alarm) { raise(alarm); return res.writeHead(409, { "content-type": "application/json" }).end(JSON.stringify(alarm)); }
        return res.writeHead(202, { "content-type": "application/json" }).end(JSON.stringify({ accepted: true, maxSeq: w.highWaterMark(source) }));
      });
      return;
    }
    res.writeHead(404).end('{"error":"not found"}');
  });

  const sweep = setInterval(() => { for (const a of w.stale()) raise(a); }, heartbeatMs);
  srv.on("close", () => clearInterval(sweep));
  srv.listen(port, () => process.stderr.write(`[aegis:witness] collecting on :${port}, store=${store}, heartbeat=${heartbeatMs}ms, authority key pinned\n`));
  await new Promise<void>(() => { /* until killed */ });
}
