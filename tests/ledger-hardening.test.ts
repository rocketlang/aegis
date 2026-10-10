// SPDX-License-Identifier: AGPL-3.0-only
// Three faults found by the sea trial of 10 October 2026, each forced here.
//
//   a full disk during a write        → the asker is told; NO fragment stays; the next row is whole; the ledger verifies
//   the fragment cannot be removed    → the error says so; the next row starts on a NEW line and can be read
//   a partial last line from before   → left as it is (nothing is ever removed); the next row starts on a new line
//   a request with no newline         → refused past the limit and the connection closed; the daemon keeps answering
//   a connection that says nothing    → closed after the idle time
//   a request sent in two pieces      → still answered (the limit must not break a slow asker)
//
// What this does NOT prove: a real full disk (the failing write is injected; red-team/ledger-disk-full.battery.sh
// fills a real, small filesystem where the box allows it), and nothing about the uid boundary (one user here).
import { describe, it, expect, afterAll } from "bun:test";
import * as fs from "fs";
import { mkdtempSync, readFileSync, writeFileSync, rmSync, existsSync } from "fs";
import { createConnection } from "net";
import { tmpdir } from "os";
import { join } from "path";
import { LedgerAuthority, appendWholeLine, type AppendIo } from "../src/core/ledger-authority.ts";
import { verifyLedgerRows } from "../src/core/ledger-sign.ts";
import { startApproverDaemon, MAX_REQUEST_BYTES } from "../src/kavach/approver-daemon.ts";

const dir = mkdtempSync(join(tmpdir(), "aegis-ledger-hardening-"));
const aegisDirBefore = process.env.AEGIS_DIR, idleBefore = process.env.AEGIS_APPROVER_IDLE_MS;
afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
  if (aegisDirBefore === undefined) delete process.env.AEGIS_DIR; else process.env.AEGIS_DIR = aegisDirBefore;
  if (idleBefore === undefined) delete process.env.AEGIS_APPROVER_IDLE_MS; else process.env.AEGIS_APPROVER_IDLE_MS = idleBefore;
});
const lines = (f: string) => readFileSync(f, "utf-8").split("\n").filter(Boolean);
const parsed = (f: string) => lines(f).map((l) => { try { return JSON.parse(l); } catch { return { __malformed: true }; } });

/** File calls that behave like a disk filling up: the next write puts HALF the bytes down and then fails. */
function fillingDisk(opts: { truncateFails?: boolean } = {}) {
  const state = { failNext: false, truncated: 0 };
  const io: AppendIo = {
    openSync: fs.openSync, fstatSync: fs.fstatSync, closeSync: fs.closeSync,
    writeSync: ((fd: number, buf: Buffer, off: number, len: number) => {
      if (!state.failNext) return fs.writeSync(fd, buf, off, len);
      state.failNext = false;
      fs.writeSync(fd, buf, off, Math.floor(len / 2));
      throw Object.assign(new Error("ENOSPC: no space left on device, write"), { code: "ENOSPC" });
    }) as typeof fs.writeSync,
    ftruncateSync: ((fd: number, len?: number) => {
      if (opts.truncateFails) throw Object.assign(new Error("EIO: i/o error, ftruncate"), { code: "EIO" });
      state.truncated++; return fs.ftruncateSync(fd, len);
    }) as typeof fs.ftruncateSync,
  };
  return { io, state };
}

describe("a row is written whole or not at all", () => {
  it("a write that fails half-way leaves the file exactly as it was", () => {
    const f = join(dir, "plain.txt"); writeFileSync(f, "one\n"); const d = fillingDisk(); d.state.failNext = true;
    expect(() => appendWholeLine(f, "two-which-is-longer\n", d.io)).toThrow("ENOSPC");
    expect(readFileSync(f, "utf-8")).toBe("one\n"); expect(d.state.truncated).toBe(1);
    appendWholeLine(f, "three\n", d.io); expect(readFileSync(f, "utf-8")).toBe("one\nthree\n");
  });

  it("a full disk under the authority: the asker is told, no fragment stays, the next row is whole and the ledger verifies", () => {
    const store = join(dir, "full"); const d = fillingDisk();
    const a = new LedgerAuthority({ storeDir: store, source: "t", appendIo: d.io, log: () => {} });
    a.record({ gate: "g", rule: "R-1" }); a.record({ gate: "g", rule: "R-2" });
    d.state.failNext = true;
    expect(() => a.record({ gate: "g", rule: "R-lost" })).toThrow("ENOSPC");
    expect(readFileSync(a.ledgerPath, "utf-8").endsWith("\n")).toBe(true); expect(lines(a.ledgerPath).length).toBe(2);
    expect(a.status().max_seq).toBe(2);                    // the row that was not written is not counted either
    const row = a.record({ gate: "g", rule: "R-3" });      // space is back
    expect(row.seq).toBe(3);
    const v = verifyLedgerRows(parsed(a.ledgerPath), a.publicKey);
    expect(v.ok).toBe(true); if (v.ok) expect(v.maxSeq).toBe(3);
  });

  it("when the fragment cannot be removed, the error says so and the next row starts on a new line and can be read", () => {
    const store = join(dir, "stuck"); const d = fillingDisk({ truncateFails: true });
    const a = new LedgerAuthority({ storeDir: store, source: "t", appendIo: d.io, log: () => {} });
    a.record({ gate: "g", rule: "R-1" });
    d.state.failNext = true;
    expect(() => a.record({ gate: "g", rule: "R-lost" })).toThrow("could not be removed");
    const row = a.record({ gate: "g", rule: "R-2" });
    const all = parsed(a.ledgerPath);
    expect(all.length).toBe(3);                                        // row 1, the fragment, row 2 — three lines, not two
    expect(all[2].seq).toBe(row.seq); expect(all[2].rule).toBe("R-2"); // the acknowledged row is readable
    expect(all[1].__malformed).toBe(true);                             // the fragment is still there, and is not hidden:
    expect(verifyLedgerRows(all, a.publicKey).ok).toBe(false);         //   the ledger does not read as clean
  });

  it("a partial last line left by an older version is not removed, and the next row is not glued to it", () => {
    const store = join(dir, "legacy"); const said: string[] = [];
    const first = new LedgerAuthority({ storeDir: store, source: "t", log: () => {} });
    first.record({ gate: "g", rule: "R-1" });
    fs.appendFileSync(first.ledgerPath, '{"ts":"2026-10-10T00:00:00.000Z","kind":"refu');   // what a full disk used to leave
    const again = new LedgerAuthority({ storeDir: store, source: "t", log: (s) => said.push(s) });
    expect(said.some((s) => s.includes("partial line"))).toBe(true);
    const row = again.record({ gate: "g", rule: "R-2" });
    const all = parsed(again.ledgerPath);
    expect(all.length).toBe(3); expect(all[1].__malformed).toBe(true); expect(all[2].seq).toBe(row.seq); expect(all[2].rule).toBe("R-2");
    expect(readFileSync(again.ledgerPath, "utf-8")).toContain('"kind":"refu\n');             // the fragment is untouched
  });
});

describe("the authority's socket has a size limit and an idle limit", () => {
  const sock = join(dir, "c.sock"); process.env.AEGIS_APPROVER_IDLE_MS = "400";
  const daemon = startApproverDaemon({ storeDir: join(dir, "daemon"), consumeSocketPath: sock, approveSocketPath: join(dir, "a.sock"), ledgerSource: "t", log: () => {} });
  afterAll(() => daemon.stop());
  const ready = async () => { for (let i = 0; i < 60 && !existsSync(sock); i++) await new Promise((r) => setTimeout(r, 25)); };
  const talk = (pieces: (string | Buffer)[], gapMs = 0, waitMs = 3000) => new Promise<{ reply: any; closed: boolean }>((resolve) => {
    let buf = ""; let closed = false; const c = createConnection(sock); c.setEncoding("utf8");
    const done = () => { let reply: any = null; try { reply = JSON.parse(buf.split("\n")[0]); } catch {} c.destroy(); resolve({ reply, closed }); };
    c.on("error", () => { closed = true; }); c.on("close", () => { closed = true; done(); }); c.on("data", (d) => { buf += d; });
    c.on("connect", async () => { for (const p of pieces) { c.write(p); if (gapMs) await new Promise((r) => setTimeout(r, gapMs)); } });
    setTimeout(done, waitMs);
  });

  it("a request with no newline is refused past the limit, the connection is closed, and the daemon keeps answering", async () => {
    await ready();
    const big = Buffer.alloc(MAX_REQUEST_BYTES + 4096, 97);
    const r = await talk([big]);
    expect(r.reply?.ok).toBe(false); expect(String(r.reply?.error)).toContain("too large"); expect(r.closed).toBe(true);
    const ok = await talk(['{"op":"ledger-status"}\n']); expect(ok.reply?.ok).toBe(true);
  });

  it("a long line that DOES end in a newline is refused too, not parsed", async () => {
    const r = await talk([Buffer.concat([Buffer.alloc(MAX_REQUEST_BYTES + 10, 97), Buffer.from("\n")])]);
    expect(r.reply?.ok).toBe(false); expect(String(r.reply?.error)).toContain("too large");
  });

  it("a connection that says nothing is closed after the idle time", async () => {
    const t0 = Date.now(); const r = await talk([], 0, 2500);
    expect(r.closed).toBe(true); expect(Date.now() - t0).toBeLessThan(2000); expect(r.reply).toBe(null);
  });

  it("a request sent in two pieces a moment apart is still answered", async () => {
    const r = await talk(['{"op":"ledger-', 'status"}\n'], 100);
    expect(r.reply?.ok).toBe(true); expect(typeof r.reply?.value?.max_seq).toBe("number");
  });

  it("a refusal is still recorded and numbered through the socket", async () => {
    const r = await talk(['{"op":"refusal","gate":"hardening-test","rule":"H-1"}\n']);
    expect(r.reply?.ok).toBe(true); expect(r.reply?.value?.seq).toBeGreaterThan(0);
  });
});
