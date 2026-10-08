// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// aegis witness — run the off-box collector (concealment rung 3). It MUST run in a trust domain the
// agent can't write as (a different host/account). It receives signed, sequenced rows, keeps its own
// append-only copy + per-source high-water-mark, and ALARMS on gap / chain / signature / stall /
// truncation. It holds only the authority PUBLIC key — it can verify, never forge.
//
//   POST /ingest/<source>   body = one signed row (JSON)         → ingests; 202, or 409 + the alarm
//   POST /heartbeat/<source> body = a signed heartbeat (JSON)     → 202, or 409 + the alarm
//   GET  /hwm/<source>                                           → { source, maxSeq }  (for reconcile)
//   GET  /health                                                 → { status, sources }
//
// Alarms are written to the witness store dir (witness-alarms.jsonl) and stderr; a stall sweep runs
// on the heartbeat interval. Env: PORT (or AEGIS_WITNESS_PORT), AEGIS_WITNESS_HOST (bind address), AEGIS_LEDGER_PUBKEY_FILE,
// AEGIS_WITNESS_STORE (default ~/.aegis/witness), AEGIS_WITNESS_HEARTBEAT_MS (default 60000).

import { createServer } from "http";
import { existsSync, readFileSync, appendFileSync, mkdirSync, readdirSync } from "fs";
import { homedir } from "os";
import { join } from "path";
import { Witness, type Alarm } from "../../core/witness";
import { verifyRowSig, type SignedRow, type Heartbeat } from "../../core/ledger-sign";

export default async function witness(args: string[]): Promise<void> {
  const flag = (n: string) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : undefined; };
  const port = parseInt(flag("--port") || process.env.AEGIS_WITNESS_PORT || process.env.PORT || "4870", 10);
  const store = flag("--store") || process.env.AEGIS_WITNESS_STORE || join(process.env.AEGIS_HOME || join(homedir(), ".aegis"), "witness");
  const heartbeatMs = parseInt(process.env.AEGIS_WITNESS_HEARTBEAT_MS || "60000", 10);
  // Absent = every interface, as before. On one box, bind it to 127.0.0.1 so it is not on the network.
  const host = flag("--host") || process.env.AEGIS_WITNESS_HOST || undefined;
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

  // The witness's own copy: every accepted row is appended to rows-<source>.jsonl in the store,
  // and read back at start, so a restart does not forget what it held. A copy that no longer
  // follows cleanly is an alarm, not a silent reset to zero.
  const rowsFile = (source: string) => join(store, `rows-${encodeURIComponent(source)}.jsonl`);
  for (const f of readdirSync(store)) {
    const m = f.match(/^rows-(.+)\.jsonl$/);
    if (!m) continue;
    const source = decodeURIComponent(m[1]);
    for (const line of readFileSync(join(store, f), "utf-8").split("\n").filter(Boolean)) {
      let alarm: Alarm | null;
      try { alarm = w.ingest(source, JSON.parse(line) as SignedRow); }
      catch { alarm = { source, kind: "chain", seq: null, detail: "the witness's own copy has an unreadable line" }; }
      if (alarm) { raise({ ...alarm, detail: `witness's own copy: ${alarm.detail}` }); break; }
    }
  }

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
        // A row the witness already holds, sent again after a lost reply, is not an alarm.
        if (typeof row?.seq === "number" && row.seq <= w.highWaterMark(source) && verifyRowSig(row, pub)) {
          return res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ accepted: false, held: true, maxSeq: w.highWaterMark(source) }));
        }
        const alarm = w.ingest(source, row);
        if (alarm) { raise(alarm); return res.writeHead(409, { "content-type": "application/json" }).end(JSON.stringify(alarm)); }
        try { appendFileSync(rowsFile(source), JSON.stringify(row) + "\n"); }
        catch (e) { raise({ source, kind: "chain", seq: row.seq, detail: `row accepted but the witness could not keep its copy: ${(e as Error).message}` }); }
        return res.writeHead(202, { "content-type": "application/json" }).end(JSON.stringify({ accepted: true, maxSeq: w.highWaterMark(source) }));
      });
      return;
    }
    const beat = url.match(/^\/heartbeat\/(.+)$/);
    if (req.method === "POST" && beat) {
      const source = decodeURIComponent(beat[1]);
      let body = "";
      req.on("data", (d) => { body += d; if (body.length > 100_000) req.destroy(); });
      req.on("end", () => {
        let hb: Heartbeat;
        try { hb = JSON.parse(body); } catch { return res.writeHead(400).end('{"error":"bad json"}'); }
        const alarm = w.heartbeat(source, hb);
        if (alarm) { raise(alarm); return res.writeHead(409, { "content-type": "application/json" }).end(JSON.stringify(alarm)); }
        return res.writeHead(202, { "content-type": "application/json" }).end(JSON.stringify({ heard: true, maxSeq: w.highWaterMark(source) }));
      });
      return;
    }
    res.writeHead(404).end('{"error":"not found"}');
  });

  const sweep = setInterval(() => { for (const a of w.stale()) raise(a); }, heartbeatMs);
  srv.on("close", () => clearInterval(sweep));
  srv.listen(port, host, () => process.stderr.write(`[aegis:witness] collecting on ${host ?? "*"}:${port}, store=${store}, heartbeat=${heartbeatMs}ms, authority key pinned\n`));
  await new Promise<void>(() => { /* until killed */ });
}
