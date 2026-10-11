// SPDX-License-Identifier: AGPL-3.0-only
// aegis red-team — who may ask for an anchor, and whose anchor is sent (2026-10-11, aegis 2.17.2).
// Found by reading our own code after Andrey Lazarev's reviews; not reported from outside.
//
// Through 2.17.1:
//   - any asker on the consume socket (the socket every gate uses) could have the authority sign a DATED
//     statement. The first dated leaf in a public log switches that ledger to one leaf a day for good, and
//     a leaf needs only this signature to be taken as the ledger's own. Whoever could ask could throw the
//     switch, and nothing on the box would show who;
//   - `aegis ledger-anchor` checked the anchor against the key the same socket had just handed it. The
//     socket is found through a pointer file the gates' own account can write: whatever answered there
//     could have its own statement sent with the box's token and written down as today's leaf, while the
//     real ledger got none that day (a hole that cannot be filled afterwards);
//   - a gate name, rule or session id went into a signed row with any characters in it, and from there
//     into what `ledger-verify` prints, mails and briefs.
//
// GAP = a dated statement for any asker; a statement by another key sent as ours; unseen characters in a row.
// One user, a temporary folder, real processes; nothing is sent to any log (--dry-run, and the log named
// does not exist). AEGIS_PROBE_REPO runs the cases against another copy. Exit: 0 closed · 1 a gap · 3 broke.
import { createServer, createConnection, type Server } from "net";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

const REPO = process.env.AEGIS_PROBE_REPO || new URL("..", import.meta.url).pathname;
const { startApproverDaemon } = await import(join(REPO, "src/kavach/approver-daemon.ts"));
const { generateLedgerKeypair } = await import(join(REPO, "src/core/ledger-sign.ts"));
const { signAnchor } = await import(join(REPO, "src/core/ledger-anchor.ts"));
const { PINNED_LEDGER_KEY_PATH } = await import(join(REPO, "src/core/refusal-ledger.ts"));
const CLI = join(REPO, "src/cli/index.ts");
let gaps = 0;
const SAFE = (id: string, ok: boolean, detail: string) => { console.log(`  [${ok ? "safe" : "GAP "}] ${id} — ${detail}`); if (!ok) gaps++; };
if (existsSync(PINNED_LEDGER_KEY_PATH)) { console.log(`BROKE — ${PINNED_LEDGER_KEY_PATH} exists on this box; run the battery script, which hides it in a private mount namespace`); process.exit(3); }

const dir = mkdtempSync(join(tmpdir(), "aegis-anchor-asker-"));
const home = join(dir, "home", ".aegis"); mkdirSync(home, { recursive: true });
const store = join(dir, "authority"), sock = join(dir, "sock"); mkdirSync(sock);
const consume = join(sock, "consume.sock"), approve = join(sock, "approve.sock"), pub = join(store, "ledger-signing.pub");
const signed = join(store, "refusals.signed.jsonl");
const jsonl = (f: string) => (existsSync(f) ? readFileSync(f, "utf-8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []);
const ask = (socket: string, req: unknown): Promise<any> => new Promise((resolve, reject) => {
  let buf = ""; const s = createConnection(socket);
  s.on("connect", () => s.write(JSON.stringify(req) + "\n")).on("data", (d) => { buf += d; const nl = buf.indexOf("\n"); if (nl !== -1) { resolve(JSON.parse(buf.slice(0, nl))); s.destroy(); } }).on("error", reject);
});
const run = async (argv: string[], env: Record<string, string> = {}): Promise<{ code: number; said: string }> => {
  const p = Bun.spawn([process.execPath, ...argv], { env: { PATH: process.env.PATH || "", HOME: join(dir, "home"), AEGIS_HOME: home, ...env }, stdout: "pipe", stderr: "pipe" });
  const said = (await new Response(p.stdout).text()) + (await new Response(p.stderr).text());
  return { code: await p.exited, said };
};
const anchorCmd = (socket: string, env: Record<string, string> = {}, ...more: string[]) =>
  run([CLI, "ledger-anchor", "--log", "http://127.0.0.1:9/nothing-listens-here", "--log-key", "0".repeat(64), "--dated", "--dry-run", "--socket", socket, ...more], env);

let daemon: any = null;
try {
  daemon = startApproverDaemon({ storeDir: store, consumeSocketPath: consume, approveSocketPath: approve, log: () => {} });
  await Bun.sleep(150);

  // 4 first, so the ledger has a row: a gate name carrying characters a terminal acts on.
  const ESC = String.fromCharCode(27);
  const g = await run(["-e", `import { recordRefusal } from ${JSON.stringify(join(REPO, "src/core/refusal-ledger.ts"))}; recordRefusal({ gate: "aegis-shield${ESC}[2K\\rall clear", rule: "KAV-001\\u202e" });`], { AEGIS_LEDGER_SOCKET: consume, AEGIS_LEDGER_PUBKEY_FILE: pub, CLAUDE_SESSION_ID: "probe" });
  const row = jsonl(signed)[0] ?? {}, local = jsonl(join(home, "refusals.jsonl"))[0] ?? {};
  const raw = JSON.stringify(row);
  SAFE("K1 unseen characters in a signed row", !/\\u001b|\\r|\\u202e/.test(raw) && local.authority_check === "verified",
    /\\u001b|\\r|\\u202e/.test(raw) ? `the signed row holds them as sent: gate ${JSON.stringify(row.gate)}` : `stored as ${JSON.stringify(row.gate)} / ${JSON.stringify(row.rule)}, and the gate's own check of the answer still holds (${local.authority_check})`);

  // 1. Any asker, the gates' socket, a dated statement.
  const d1 = await ask(consume, { op: "anchor", dated: true });
  SAFE("K2 a dated anchor for any asker", d1.ok === false, d1.ok ? `signed for ${d1.value?.day}: whoever can ask can switch this ledger to one leaf a day` : "refused on the consume socket");
  const d2 = await ask(consume, { op: "anchor" }), d3 = await ask(approve, { op: "anchor", dated: true });
  SAFE("K3 undated for a gate, dated for an operator", d2.ok === true && d2.value?.day === undefined && d3.ok === true && typeof d3.value?.day === "string",
    `undated on consume: ${d2.ok}; dated on approve: ${d3.ok ? d3.value.day : d3.error}`);
  const d4 = await ask(consume, { op: "approve", code: "00000000" });
  SAFE("K3b the approve op is still refused on the consume socket", d4.ok === false, d4.ok ? "ACCEPTED" : "refused");

  // 2. The daily command, pointed at the gates' socket as it always was, still gets its dated statement.
  const c1 = await anchorCmd(consume, { AEGIS_LEDGER_PUBKEY_FILE: pub });
  SAFE("K4 the daily command still works", c1.code === 0 && /stated for \d{4}-\d\d-\d\d/.test(c1.said), c1.code === 0 ? "it asked the approve socket beside the consume socket and got today's statement (dry run, nothing sent)" : `exit ${c1.code}: ${c1.said.trim().split("\n").pop()}`);

  // 3. Something else answers at the socket, with its own key and its own statement.
  const other = generateLedgerKeypair();
  const srv: Server = createServer((c) => { let buf = ""; c.on("data", (d) => { buf += d; const nl = buf.indexOf("\n"); if (nl === -1) return; const req = JSON.parse(buf.slice(0, nl));
    const value = req.op === "ledger-status" ? { rows: 9, max_seq: 9, public_key: other.publicKey, source: "ankr-box", receipts: true } : signAnchor("ankr-box", 9, "ab".repeat(32), other.privateKey, other.publicKey, new Date().toISOString().slice(0, 10));
    c.write(JSON.stringify({ ok: true, value }) + "\n"); c.end(); }); });
  const fakePath = join(dir, "fake.sock"); await new Promise<void>((r) => srv.listen(fakePath, () => r()));
  const c2 = await anchorCmd(fakePath, { AEGIS_LEDGER_PUBKEY_FILE: pub });
  SAFE("K5 another key's statement, with the ledger key pinned", c2.code === 2 && /not the authority whose key is pinned/.test(c2.said), c2.code === 2 ? "refused: nothing would be sent, nothing written down as today's leaf" : `exit ${c2.code}: it would send the stranger's statement as this ledger's (${c2.said.trim().split("\n").pop()?.slice(0, 110)})`);
  const c3 = await anchorCmd(fakePath);
  SAFE("K6 the same with no key pinned", /no ledger key is pinned/.test(c3.said), /no ledger key is pinned/.test(c3.said) ? "it cannot tell, and says so" : "it cannot tell, and does not say so");
  srv.close();
} catch (e) {
  console.log(`BROKE — ${(e as Error).stack || e}`); try { daemon?.stop(); } catch { /* */ } rmSync(dir, { recursive: true, force: true }); process.exit(3);
}
try { daemon?.stop(); } catch { /* */ }
rmSync(dir, { recursive: true, force: true });
console.log(`\n  ledger-anchor-asker: ${gaps} gap(s)`);
process.exit(gaps > 0 ? 1 : 0);
