// SPDX-License-Identifier: AGPL-3.0-only
// aegis red-team — something that is not the authority answers the gate (2026-10-11, aegis 2.16.3).
// Reported by Andrey Lazarev against 2.16.2, with a probe; this is that probe grown into a battery.
//
// Before: the gate took any reply that said "ok" and carried a number as a signed row. A socket the
// agent's uid controls, named in the pointer file, answered {"ok":true,"value":{"seq":42}}: the local
// row read `authority_seq: 42`, nothing was said on stderr, and the real ledger never saw the refusal.
// With the pointer file deleted the local row carried no number and no reason. Nothing compared the
// local file with the signed ledger.
//
// Now, with the ledger's public key pinned for the gate:
//   - a real authority's answer is checked and the local row says "verified";
//   - a bare "ok, 42" is refused, said on stderr, written as NOT signed;
//   - a genuine row and receipt copied from an earlier answer are refused (the receipt is for another ask);
//   - an answer signed by another key is refused;
//   - a missing pointer file is said aloud.
// And with no key pinned (the gate cannot check), `aegis ledger-verify --local` finds both afterwards.
//
// GAP = a refusal reads as signed, or goes unsaid, when the authority never recorded it.
// Everything is in a temporary folder and one user: this proves the checks, not the uid boundary. The
// pin is given through the environment here; on a real box it is /etc/aegis/ledger-signing.pub.
// Exit: 0 all closed · 1 a gap · 3 broke.
import { createServer, createConnection, type Server } from "net";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { startApproverDaemon } from "../src/kavach/approver-daemon.ts";
import { generateLedgerKeypair, signLedgerRow, signReceipt } from "../src/core/ledger-sign.ts";
import { PINNED_LEDGER_KEY_PATH } from "../src/core/refusal-ledger.ts";

const REPO = new URL("..", import.meta.url).pathname;
let gaps = 0;
const SAFE = (id: string, ok: boolean, detail: string) => { console.log(`  [${ok ? "safe" : "GAP "}] ${id} — ${detail}`); if (!ok) gaps++; };
const broke = (why: string): never => { console.log(`BROKE — ${why}`); process.exit(3); };

if (existsSync(PINNED_LEDGER_KEY_PATH)) broke(`${PINNED_LEDGER_KEY_PATH} exists on this box and would be the key for every gate here; run the battery script, which hides it in a private mount namespace`);

const dir = mkdtempSync(join(tmpdir(), "aegis-fake-authority-"));
const home = join(dir, "home", ".aegis"); mkdirSync(home, { recursive: true });
const store = join(dir, "authority");
const consume = join(dir, "consume.sock");
const pub = join(store, "ledger-signing.pub");
const signed = join(store, "refusals.signed.jsonl");
const local = join(home, "refusals.jsonl");
const pointer = join(home, "ledger-socket");
const jsonl = (f: string) => (existsSync(f) ? readFileSync(f, "utf-8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []);

// The gate runs in its own process, as a hook does: its ask is synchronous.
async function gate(session: string, pinned: boolean): Promise<{ row: Record<string, unknown>; stderr: string }> {
  const env: Record<string, string> = { PATH: process.env.PATH || "", HOME: join(dir, "home"), AEGIS_HOME: home, CLAUDE_SESSION_ID: session };
  if (pinned) env.AEGIS_LEDGER_PUBKEY_FILE = pub;
  const p = Bun.spawn([process.execPath, "-e", `import { recordRefusal } from ${JSON.stringify(join(REPO, "src/core/refusal-ledger.ts"))}; recordRefusal({ gate: "aegis-destructive", rule: "KAV-001" });`], { env, stdout: "ignore", stderr: "pipe" });
  const stderr = await new Response(p.stderr).text(); await p.exited;
  const rows = jsonl(local);
  return { row: rows[rows.length - 1] ?? {}, stderr };
}
const ask = (socket: string, req: unknown): Promise<any> => new Promise((resolve, reject) => {
  let buf = ""; const s = createConnection(socket);
  s.on("connect", () => s.write(JSON.stringify(req) + "\n")).on("data", (d) => { buf += d; const nl = buf.indexOf("\n"); if (nl !== -1) { resolve(JSON.parse(buf.slice(0, nl))); s.destroy(); } }).on("error", reject);
});
let fakeN = 0;
function fake(reply: (req: any) => unknown): Promise<{ path: string; asked: () => number; close: () => void }> {
  const path = join(dir, `fake-${++fakeN}.sock`); let asked = 0;
  const srv: Server = createServer((c) => { let buf = ""; c.on("data", (d) => { buf += d; const nl = buf.indexOf("\n"); if (nl === -1) return; asked++; c.write(JSON.stringify(reply(JSON.parse(buf.slice(0, nl)))) + "\n"); c.end(); }); });
  return new Promise((resolve) => srv.listen(path, () => resolve({ path, asked: () => asked, close: () => srv.close() })));
}
const verify = async (...more: string[]): Promise<{ code: number; said: string }> => {
  const p = Bun.spawn([process.execPath, join(REPO, "src/cli/index.ts"), "ledger-verify", signed, "--local", local, ...more], { env: { PATH: process.env.PATH || "", HOME: join(dir, "home"), AEGIS_HOME: home, AEGIS_LEDGER_PUBKEY_FILE: pub }, stdout: "pipe", stderr: "pipe" });
  const said = (await new Response(p.stdout).text()) + (await new Response(p.stderr).text());
  return { code: await p.exited, said };
};

let daemon: ReturnType<typeof startApproverDaemon> | null = null;
try {
  daemon = startApproverDaemon({ storeDir: store, consumeSocketPath: consume, approveSocketPath: join(dir, "approve.sock"), log: () => {} });
  const rowsNow = () => jsonl(signed).length;

  // ── the control: the real authority, key pinned ─────────────────────────────────────────────
  writeFileSync(pointer, consume + "\n");
  let g = await gate("real-pinned", true);
  SAFE("control: the real authority's answer is checked and accepted", g.row.authority_seq === 1 && g.row.authority_check === "verified" && rowsNow() === 1 && !g.stderr.includes("NOT signed"),
    `local row: seq ${g.row.authority_seq}, ${g.row.authority_check}; signed ledger rows: ${rowsNow()}`);

  // ── the reported attack: a bare "ok, 42" from a socket of the agent's own ───────────────────
  const bare = await fake(() => ({ ok: true, value: { seq: 42 } }));
  writeFileSync(pointer, bare.path + "\n");
  g = await gate("fake-bare", true);
  SAFE("a bare 'ok, 42' is not taken as signed", bare.asked() === 1 && g.row.session === "fake-bare" && g.row.authority_seq === undefined && typeof g.row.authority_error === "string" && g.stderr.includes("NOT signed") && rowsNow() === 1,
    `fake asked ${bare.asked()}x; local row: seq ${g.row.authority_seq}, error '${String(g.row.authority_error).slice(0, 70)}…'; stderr ${g.stderr.includes("NOT signed") ? "says NOT signed" : "silent"}`);
  bare.close();

  // ── a genuine answer, copied: the same refusal asked of the real authority earlier, played back ──
  const earlier = await ask(consume, { op: "refusal", gate: "aegis-destructive", rule: "KAV-001", kind: "refused", session: "fake-replay", nonce: "ab".repeat(16) });
  const replay = await fake(() => earlier);
  writeFileSync(pointer, replay.path + "\n");
  const before = rowsNow();
  g = await gate("fake-replay", true);
  SAFE("a genuine row and receipt from an earlier answer are refused", earlier.ok && !!earlier.value.receipt && g.row.authority_seq === undefined && String(g.row.authority_error).includes("another ask") && rowsNow() === before,
    `the copied answer was for seq ${earlier.value?.seq}; local row: seq ${g.row.authority_seq}, error '${String(g.row.authority_error).slice(0, 90)}…'`);
  replay.close();

  // ── a whole authority of the agent's own, with its own key ──────────────────────────────────
  const mine = generateLedgerKeypair();
  const forger = await fake((req) => {
    const row = signLedgerRow({ ts: new Date().toISOString(), kind: "refused", gate: req.gate, rule: req.rule, session: req.session }, 3, "", mine.privateKey);
    return { ok: true, value: { seq: 3, row, receipt: signReceipt(req.nonce, row, mine.privateKey) } };
  });
  writeFileSync(pointer, forger.path + "\n");
  g = await gate("fake-own-key", true);
  SAFE("an answer signed by another key is refused", forger.asked() === 1 && g.row.authority_seq === undefined && String(g.row.authority_error).includes("not by that key"),
    `local row: seq ${g.row.authority_seq}, error '${String(g.row.authority_error).slice(0, 90)}…'`);
  forger.close();

  // ── the quieter version: the pointer file deleted ──────────────────────────────────────────
  unlinkSync(pointer);
  g = await gate("no-pointer-pinned", true);
  SAFE("with a key pinned, a missing pointer file is said aloud", g.row.session === "no-pointer-pinned" && typeof g.row.authority_error === "string" && g.stderr.includes("NOT signed"),
    `local row: error '${String(g.row.authority_error).slice(0, 80)}…'`);

  // ── so far every row is honest: the two files agree ────────────────────────────────────────
  let v = await verify();
  SAFE("control: ledger-verify --local is clean while the local file tells the truth", v.code === 0 && v.said.includes("agrees"), `exit ${v.code}`);

  // ── no key pinned: the gate cannot check. The comparison afterwards must find it. ──────────
  const bare2 = await fake(() => ({ ok: true, value: { seq: 42 } }));
  writeFileSync(pointer, bare2.path + "\n");
  g = await gate("fake-bare-unpinned", false);
  const fooled = g.row.authority_seq === 42;
  SAFE("with no key pinned the row does not claim to be verified", fooled && g.row.authority_check === "unchecked", `local row: seq ${g.row.authority_seq}, ${g.row.authority_check}`);
  v = await verify();
  SAFE("ledger-verify --local finds the number the authority never gave", v.code === 1 && v.said.includes("LOCAL ROW NOT IN THE SIGNED LEDGER") && v.said.includes("seq 42"), `exit ${v.code}`);
  bare2.close();

  // put the honest state back, then the silent row
  writeFileSync(local, jsonl(local).filter((r) => r.session !== "fake-bare-unpinned").map((r) => JSON.stringify(r)).join("\n") + "\n");
  unlinkSync(pointer);
  g = await gate("no-pointer-unpinned", false);
  v = await verify();
  SAFE("ledger-verify --local finds a refusal with no number and no reason", g.row.authority_seq === undefined && g.row.authority_error === undefined && v.code === 1 && v.said.includes("NOT SIGNED AND NOT SAID"), `exit ${v.code}`);
} catch (e) {
  broke((e as Error).message);
} finally {
  try { daemon?.stop(); } catch { /* */ }
  try { rmSync(dir, { recursive: true, force: true }); } catch { /* */ }
}
console.log(gaps === 0 ? "\nAll closed." : `\n${gaps} gap(s).`);
process.exit(gaps === 0 ? 0 : 1);
