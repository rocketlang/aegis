// SPDX-License-Identifier: AGPL-3.0-only
// The signed refusal ledger, WIRED: a real gate refuses, the separate authority numbers and signs
// the row, a real witness process keeps its own copy, and the failures are forced.
//
//   a real refusal (check-budget)        → exit 2, a signed row at the authority, seq in the local row
//   five refusals at once                → five different numbers, the chain still verifies
//   the authority unreachable            → STILL exit 2, the local row and stderr say it was not signed
//   the witness restarted                → it still holds what it held (its own copy, on disk)
//   the on-box ledger cut short          → the witness alarms `truncation`; ledger-verify --witness exits 1
//   the authority gone quiet             → the witness alarms `stall`
//   heartbeat ahead of the witness       → `gap` (a row that never arrived is not quiet)
//
// What this does NOT prove: the uid boundary. Everything here runs as one user, so the key is
// readable by the test. The boundary is the operating system's and is proven on a disposable host
// (red-team/point1-uid-boundary.disposable.sh). It also does not prove a gate that refuses and
// never asks is caught — it is not.
import { describe, it, expect, beforeAll, afterAll } from "bun:test";
import { existsSync, readFileSync, mkdtempSync, writeFileSync, statSync } from "fs";
import { createServer } from "net";
import { tmpdir } from "os";
import { join } from "path";
import { TestHarness, dailyPeriodKey, now } from "../src/test-agents/harness.ts";
import { startApproverDaemon } from "../src/kavach/approver-daemon.ts";
import { verifyLedgerFile } from "../src/core/refusal-ledger.ts";
import { generateLedgerKeypair, signHeartbeat, signLedgerRow, rowHash } from "../src/core/ledger-sign.ts";
import { Witness } from "../src/core/witness.ts";

const ROOT = new URL("..", import.meta.url).pathname;
const SOURCE = "test-box";
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const lines = (file: string) =>
  existsSync(file) ? readFileSync(file, "utf-8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : [];

function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const s = createServer();
    s.listen(0, "127.0.0.1", () => { const p = (s.address() as { port: number }).port; s.close(() => resolve(p)); });
  });
}

async function until(what: () => boolean | Promise<boolean>, ms = 8000): Promise<boolean> {
  const end = Date.now() + ms;
  while (Date.now() < end) { if (await what()) return true; await sleep(100); }
  return false;
}

function overBudget(name: string): TestHarness {
  const h = new TestHarness(name);
  h.setup({ enforcement: { mode: "enforce" }, budget: { daily_limit_usd: 5 } });
  h.seedDb((db) => {
    db.run(
      "INSERT OR REPLACE INTO budget_state (period, spent_usd, limit_usd, last_updated) VALUES (?, ?, ?, ?)",
      [dailyPeriodKey(), 6.0, 5.0, now()],
    );
  });
  return h;
}

const dir = mkdtempSync(join(tmpdir(), "aegis-ledger-authority-"));
const store = join(dir, "authority");
const witnessStore = join(dir, "witness");
const consume = join(dir, "consume.sock");
const approve = join(dir, "approve.sock");
const local = join(dir, "local-refusals.jsonl");
const signed = join(store, "refusals.signed.jsonl");
const pub = join(store, "ledger-signing.pub");
const alarmsFile = join(witnessStore, "witness-alarms.jsonl");
let port = 0;
let url = "";
let daemon: ReturnType<typeof startApproverDaemon> | null = null;
let witness: ReturnType<typeof Bun.spawn> | null = null;
const quiet = () => { /* daemon chatter is not the test's output */ };

function startDaemon() {
  daemon = startApproverDaemon({
    storeDir: store, consumeSocketPath: consume, approveSocketPath: approve,
    witnessUrl: url, ledgerSource: SOURCE, ledgerHeartbeatMs: 250, log: quiet,
  });
}
async function startWitness() {
  witness = Bun.spawn(["bun", "src/cli/index.ts", "witness", "--port", String(port), "--store", witnessStore], {
    cwd: ROOT, stdout: "ignore", stderr: "ignore",
    env: { ...process.env, AEGIS_LEDGER_PUBKEY_FILE: pub, AEGIS_WITNESS_HEARTBEAT_MS: "1200" },
  });
  expect(await until(async () => { try { return (await fetch(`${url}/health`)).ok; } catch { return false; } })).toBe(true);
}
const held = async (): Promise<number> => ((await (await fetch(`${url}/hwm/${SOURCE}`)).json()) as { maxSeq: number }).maxSeq;
const alarms = (kind: string) => lines(alarmsFile).filter((a) => a.kind === kind && a.source === SOURCE);
const refuse = (h: TestHarness, session: string, socket = consume) =>
  h.callHook("check-budget", {}, { CLAUDE_SESSION_ID: session, CLAUDE_CODE_SESSION_ID: "", AEGIS_LEDGER_SOCKET: socket, AEGIS_REFUSAL_LEDGER: local });

beforeAll(async () => {
  port = await freePort();
  url = `http://127.0.0.1:${port}`;
  startDaemon();          // makes the key; the witness needs the public half to start
  await startWitness();
});
afterAll(() => {
  try { daemon?.stop(); } catch { /* */ }
  try { witness?.kill(); } catch { /* */ }
});

describe("signed refusal ledger, wired through the authority", () => {
  it("a real gate refusal becomes a signed, numbered row the gate did not write", async () => {
    const h = overBudget("ledger-authority-1");
    try {
      const r = await refuse(h, "wired-1");
      expect(r.exitCode).toBe(2);
      const mine = lines(local);
      expect(mine.length).toBe(1);
      expect(mine[0].authority_seq).toBe(1);
      expect(mine[0].authority_error).toBeUndefined();
      const rows = lines(signed);
      expect(rows.length).toBe(1);
      expect(rows[0].gate).toBe("aegis-budget");
      expect(rows[0].session).toBe("wired-1");
      expect(rows[0].seq).toBe(1);
      expect(typeof rows[0].sig).toBe("string");
      expect(verifyLedgerFile(signed, readFileSync(pub, "utf-8"))).toEqual({ ok: true, rows: 1, maxSeq: 1 });
      expect(statSync(join(store, "ledger-signing.key")).mode & 0o077).toBe(0);
    } finally { h.cleanup(); }
  }, 30000);

  it("five refusals at once take five different numbers", async () => {
    const hs = [0, 1, 2, 3, 4].map((i) => overBudget(`ledger-authority-par-${i}`));
    try {
      const rs = await Promise.all(hs.map((h, i) => refuse(h, `wired-par-${i}`)));
      expect(rs.map((r) => r.exitCode)).toEqual([2, 2, 2, 2, 2]);
      const v = verifyLedgerFile(signed, readFileSync(pub, "utf-8"));
      expect(v).toEqual({ ok: true, rows: 6, maxSeq: 6 });
      const seqs = lines(local).map((r) => r.authority_seq).sort((a, b) => a - b);
      expect(seqs).toEqual([1, 2, 3, 4, 5, 6]);
    } finally { hs.forEach((h) => h.cleanup()); }
  }, 60000);

  it("the witness holds its own copy of every row", async () => {
    expect(await until(async () => (await held()) === 6)).toBe(true);
    const copy = lines(join(witnessStore, `rows-${SOURCE}.jsonl`));
    expect(copy.map((r) => r.seq)).toEqual([1, 2, 3, 4, 5, 6]);
    expect(alarms("gap").length).toBe(0);
  }, 30000);

  it("still refuses, and says the row is unsigned, when the authority cannot be reached", async () => {
    const h = overBudget("ledger-authority-unreachable");
    try {
      const r = await refuse(h, "wired-unreachable", join(dir, "no-such.sock"));
      expect(r.exitCode).toBe(2);
      expect(r.stderr).toContain("NOT signed");
      const last = lines(local).pop();
      expect(last.session).toBe("wired-unreachable");
      expect(last.authority_seq).toBeUndefined();
      expect(String(last.authority_error)).toContain("unreachable");
      expect(lines(signed).length).toBe(6);
    } finally { h.cleanup(); }
  }, 30000);

  it("a restarted witness still holds what it held", async () => {
    witness!.kill();
    await witness!.exited;
    await startWitness();
    expect(await held()).toBe(6);
    expect(alarms("gap").length).toBe(0);
    expect(alarms("chain").length).toBe(0);
  }, 30000);

  it("a ledger cut short on-box is a truncation alarm at the witness, and ledger-verify --witness fails", async () => {
    daemon!.stop();
    const kept = readFileSync(signed, "utf-8").split("\n").filter(Boolean).slice(0, 4);
    writeFileSync(signed, kept.join("\n") + "\n");
    // On its own the cut file reads clean — that is the limit of an on-box check.
    expect(verifyLedgerFile(signed, readFileSync(pub, "utf-8"))).toEqual({ ok: true, rows: 4, maxSeq: 4 });
    const v = Bun.spawn(["bun", "src/cli/index.ts", "ledger-verify", signed, "--witness", url, "--source", SOURCE], {
      cwd: ROOT, stdout: "pipe", stderr: "pipe", env: { ...process.env, AEGIS_LEDGER_PUBKEY_FILE: pub },
    });
    const [code, err] = await Promise.all([v.exited, new Response(v.stderr).text()]);
    expect(code).toBe(1);
    expect(err).toContain("TRUNCATION");
    startDaemon();          // the authority comes back on the cut file and states where it stands
    expect(await until(() => alarms("truncation").length > 0)).toBe(true);
  }, 30000);

  it("an authority gone quiet is a stall alarm", async () => {
    daemon!.stop();
    expect(await until(() => alarms("stall").length > 0, 6000)).toBe(true);
  }, 30000);
});

describe("witness heartbeat", () => {
  const { publicKey, privateKey } = generateLedgerKeypair();
  const other = generateLedgerKeypair();
  const row1 = signLedgerRow({ ts: "2026-01-01T00:00:00.000Z", kind: "refused", gate: "g", rule: null, session: null }, 1, "", privateKey);
  const beat = (max_seq: number, tail_hash: string, ts: string, key = privateKey) =>
    signHeartbeat({ source: "s", max_seq, tail_hash, ts }, key);

  it("an authority ahead of the witness is a gap: a row that never arrived is not quiet", () => {
    const w = new Witness(publicKey, 1000);
    const a = w.heartbeat("s", beat(1, rowHash(row1), "2026-01-01T00:00:01.000Z"), 0);
    expect(a?.kind).toBe("gap");
  });

  it("level with the witness is clean; a different tail at the same number is a chain alarm", () => {
    const w = new Witness(publicKey, 1000);
    expect(w.ingest("s", row1, 0)).toBeNull();
    expect(w.heartbeat("s", beat(1, rowHash(row1), "2026-01-01T00:00:01.000Z"), 1)).toBeNull();
    expect(w.heartbeat("s", beat(1, "f".repeat(64), "2026-01-01T00:00:02.000Z"), 2)?.kind).toBe("chain");
  });

  it("a heartbeat signed by another key, or for another source, is refused", () => {
    const w = new Witness(publicKey, 1000);
    expect(w.heartbeat("s", beat(0, "", "2026-01-01T00:00:01.000Z", other.privateKey), 0)?.kind).toBe("signature");
    expect(w.heartbeat("t", beat(0, "", "2026-01-01T00:00:01.000Z"), 0)?.kind).toBe("signature");
  });

  it("a replayed heartbeat does not keep a source alive", () => {
    const w = new Witness(publicKey, 1000);
    const hb = beat(0, "", "2026-01-01T00:00:01.000Z");
    expect(w.heartbeat("s", hb, 0)).toBeNull();
    expect(w.heartbeat("s", hb, 900)).toBeNull();      // the same heartbeat again: ignored
    expect(w.stale(1500).map((a) => a.kind)).toEqual(["stall"]);
  });

  it("a row cannot be passed off as a heartbeat", () => {
    const w = new Witness(publicKey, 1000);
    const forged = { source: "s", max_seq: 0, tail_hash: "", ts: "2026-01-01T00:00:01.000Z", sig: row1.sig };
    expect(w.heartbeat("s", forged, 0)?.kind).toBe("signature");
  });
});
