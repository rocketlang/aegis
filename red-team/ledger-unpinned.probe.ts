// SPDX-License-Identifier: AGPL-3.0-only
// aegis red-team — an authority is set up and nobody pinned its key (2026-10-11, aegis 2.17.1).
// Pointed out by Andrey Lazarev against 2.17.0: nothing in the package puts the ledger key at
// /etc/aegis/ledger-signing.pub, so an install with an authority ran with every answer "unchecked" and
// nothing said. His probe (a socket of the agent's own answering "ok, 42") still passed quietly there.
//
// Now: the gate says NOT CHECKED on stderr each time; `aegis ledger-pin` is the step that was missing,
// and it must not be a new way in: it takes the key from a file the person names, never from the socket.
//
// GAP = an unchecked answer goes unsaid, or ledger-pin can be made to pin a key it should not.
// One user, a temporary folder. AEGIS_PROBE_REPO runs the same cases against another copy of the
// package (an installed 2.17.0, to see them red). Exit: 0 all closed · 1 a gap · 3 broke.
import { createServer, type Server } from "net";
import { chmodSync, existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

const REPO = process.env.AEGIS_PROBE_REPO || new URL("..", import.meta.url).pathname;
const { startApproverDaemon } = await import(join(REPO, "src/kavach/approver-daemon.ts"));
const { generateLedgerKeypair } = await import(join(REPO, "src/core/ledger-sign.ts"));
const { PINNED_LEDGER_KEY_PATH } = await import(join(REPO, "src/core/refusal-ledger.ts"));
const CLI = join(REPO, "src/cli/index.ts");
let gaps = 0;
const SAFE = (id: string, ok: boolean, detail: string) => { console.log(`  [${ok ? "safe" : "GAP "}] ${id} — ${detail}`); if (!ok) gaps++; };
const broke = (why: string): never => { console.log(`BROKE — ${why}`); process.exit(3); };
if (existsSync(PINNED_LEDGER_KEY_PATH)) broke(`${PINNED_LEDGER_KEY_PATH} exists on this box; run the battery script, which hides it in a private mount namespace`);

const dir = mkdtempSync(join(tmpdir(), "aegis-unpinned-"));
const home = join(dir, "home", ".aegis"); mkdirSync(home, { recursive: true });
const store = join(dir, "authority"), consume = join(dir, "consume.sock"), pub = join(store, "ledger-signing.pub");
const local = join(home, "refusals.jsonl"), pin = join(dir, "etc-aegis", "ledger-signing.pub");
const jsonl = (f: string) => (existsSync(f) ? readFileSync(f, "utf-8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []);
const baseEnv = () => ({ PATH: process.env.PATH || "", HOME: join(dir, "home"), AEGIS_HOME: home });
const run = async (argv: string[], env: Record<string, string> = {}): Promise<{ code: number; said: string }> => {
  const p = Bun.spawn([process.execPath, ...argv], { env: { ...baseEnv(), ...env }, stdout: "pipe", stderr: "pipe" });
  const said = (await new Response(p.stdout).text()) + (await new Response(p.stderr).text());
  return { code: await p.exited, said };
};
const gate = async (socket: string, env: Record<string, string> = {}) => {
  const r = await run(["-e", `import { recordRefusal } from ${JSON.stringify(join(REPO, "src/core/refusal-ledger.ts"))}; recordRefusal({ gate: "aegis-destructive", rule: "KAV-001" });`], { AEGIS_LEDGER_SOCKET: socket, CLAUDE_SESSION_ID: "probe", ...env });
  const rows = jsonl(local);
  return { row: rows[rows.length - 1] ?? {}, stderr: r.said };
};
let fakeN = 0;
const fake = (reply: (req: any) => unknown): Promise<{ path: string; close: () => void }> => {
  const path = join(dir, `fake-${++fakeN}.sock`);
  const srv: Server = createServer((c) => { let buf = ""; c.on("data", (d) => { buf += d; const nl = buf.indexOf("\n"); if (nl === -1) return; c.write(JSON.stringify(reply(JSON.parse(buf.slice(0, nl)))) + "\n"); c.end(); }); });
  return new Promise((resolve) => srv.listen(path, () => resolve({ path, close: () => srv.close() })));
};
const pinCmd = (...a: string[]) => run([CLI, "ledger-pin", ...a]);
const hasPin = existsSync(join(REPO, "src/cli/commands/ledger-pin.ts"));

let daemon: any = null;
try {
  daemon = startApproverDaemon({ storeDir: store, consumeSocketPath: consume, approveSocketPath: join(dir, "approve.sock"), log: () => {} });
  await Bun.sleep(150);
  const realKey = readFileSync(pub, "utf-8");

  // 1. His probe, on an install where nobody pinned a key.
  const f42 = await fake(() => ({ ok: true, value: { seq: 42 } }));
  const a = await gate(f42.path);
  SAFE("U1 a false authority, no key pinned", /NOT CHECKED/.test(a.stderr) && a.row.authority_check === "unchecked",
    /NOT CHECKED/.test(a.stderr) ? "the local row says unchecked and stderr says the number was NOT CHECKED" : `the row reads authority_seq ${a.row.authority_seq} and nothing was said on stderr`);
  f42.close();
  const b = await gate(consume);
  SAFE("U2 the real authority, no key pinned", /NOT CHECKED/.test(b.stderr), /NOT CHECKED/.test(b.stderr) ? "said on stderr too: unpinned is unchecked, whoever answers" : "a real answer nobody checked is not said to be unchecked");

  if (!hasPin) { SAFE("U3–U9 ledger-pin", false, "this copy of the package has no `aegis ledger-pin`: nothing in it pins the key"); }
  else {
    // 3. The socket must not choose the key. A false authority offers its own; the person names the real file.
    const other = generateLedgerKeypair();
    const liar = await fake(() => ({ ok: true, value: { public_key: other.publicKey, receipts: true, rows: 0, max_seq: 0 } }));
    const c = await pinCmd("--from", pub, "--socket", liar.path, "--to", pin);
    SAFE("U3 what answers at the socket has another key", c.code === 1 && !existsSync(pin), c.code === 1 ? "refused; nothing written" : `exit ${c.code}, pin ${existsSync(pin) ? "WRITTEN" : "absent"}`);
    // 4. ...and the other way round: the person is handed the attacker's key file; the real authority is asked.
    const evil = join(dir, "evil.pub"); writeFileSync(evil, other.publicKey, { mode: 0o644 });
    const d = await pinCmd("--from", evil, "--socket", consume, "--to", pin);
    SAFE("U4 a key file that is not the authority's", d.code === 1 && !existsSync(pin), d.code === 1 ? "refused: the authority says its key is another one" : `exit ${d.code}`);
    liar.close();
    // 5. An authority older than 2.16.3 has the key and no receipts: pinning would turn every refusal into "not signed".
    const old = await fake(() => ({ ok: true, value: { public_key: realKey, rows: 3, max_seq: 3 } }));
    const e = await pinCmd("--from", pub, "--socket", old.path, "--to", pin);
    SAFE("U5 an authority older than 2.16.3", e.code === 1 && /older than 2\.16\.3/.test(e.said) && !existsSync(pin), e.code === 1 ? "refused, and says to upgrade the authority first" : `exit ${e.code}`);
    old.close();
    // 6. The source file must be one only its owner can write, and not a link.
    const loose = join(dir, "loose.pub"); writeFileSync(loose, realKey); chmodSync(loose, 0o666);
    const link = join(dir, "link.pub"); symlinkSync(pub, link);
    const g1 = await pinCmd("--from", loose, "--socket", consume, "--to", pin), g2 = await pinCmd("--from", link, "--socket", consume, "--to", pin);
    SAFE("U6 a key file anyone can write, or a link", g1.code === 1 && g2.code === 1 && !existsSync(pin), `world-writable: exit ${g1.code}; link: exit ${g2.code}`);
    // 7. No socket named and none configured: it does not pin on faith unless told to.
    const h = await pinCmd("--from", pub, "--to", pin);
    SAFE("U7 no authority to ask", h.code === 1 && !existsSync(pin), h.code === 1 ? "refused without --unchecked" : `exit ${h.code}`);
    // 8. The real thing. Then a gate given that file checks, and the false authority is refused aloud.
    const ok = await pinCmd("--from", pub, "--socket", consume, "--to", pin);
    const mode = existsSync(pin) ? statSync(pin).mode & 0o777 : 0;
    SAFE("U8 the real authority's key", ok.code === 0 && mode === 0o644 && readFileSync(pin, "utf-8") === realKey, ok.code === 0 ? `pinned, mode ${mode.toString(8)}` : `exit ${ok.code}: ${ok.said.trim().split("\n")[0]}`);
    const v = await gate(consume, { AEGIS_LEDGER_PUBKEY_FILE: pin });
    const f2 = await fake(() => ({ ok: true, value: { seq: 42 } }));
    const w = await gate(f2.path, { AEGIS_LEDGER_PUBKEY_FILE: pin }); f2.close();
    SAFE("U8b with the key pinned", v.row.authority_check === "verified" && !/NOT/.test(v.stderr) && typeof w.row.authority_error === "string" && /NOT signed/.test(w.stderr),
      `real authority: ${v.row.authority_check}, quiet; false one: ${w.row.authority_error ? "refused and said" : "ACCEPTED"}`);
    // 9. A pin is not changed by accident.
    const i = await pinCmd("--from", evil, "--unchecked", "--to", pin);
    SAFE("U9 another key over an existing pin", i.code === 1 && readFileSync(pin, "utf-8") === realKey, i.code === 1 ? "refused without --replace; the pin is unchanged" : `exit ${i.code}`);
  }

  // 10. The verifier says which key it used; with none named and none pinned it is the home copy, and it says whose that is.
  writeFileSync(join(home, "ledger-signing.pub"), realKey);
  const lv = await run([CLI, "ledger-verify", join(store, "refusals.signed.jsonl")]);
  SAFE("U10 the verifier names its key", /key: .*the gates' own account can write/.test(lv.said), /key: /.test(lv.said) ? "it says the key came from a file the gates' own account can write" : "it used the copy in the aegis home and did not say so");

  // 11. The consume socket's mode is the daemon's to state, not something left to whoever provisions.
  daemon.stop(); daemon = null;
  const s2 = join(dir, "c2.sock");
  daemon = startApproverDaemon({ storeDir: store, consumeSocketPath: s2, approveSocketPath: join(dir, "a2.sock"), consumeSocketMode: 0o666, log: () => {} });
  await Bun.sleep(150);
  const m = statSync(s2).mode & 0o777, am = statSync(join(dir, "a2.sock")).mode & 0o777;
  SAFE("U11 consume socket mode 666 when asked", m === 0o666 && am === 0o660, `consume ${m.toString(8)}, approve ${am.toString(8)}`);
} catch (e) {
  console.log(`BROKE — ${(e as Error).stack || e}`); try { daemon?.stop(); } catch { /* */ } rmSync(dir, { recursive: true, force: true }); process.exit(3);
}
try { daemon?.stop(); } catch { /* */ }
rmSync(dir, { recursive: true, force: true });
console.log(`\n  ledger-unpinned: ${gaps} gap(s)`);
process.exit(gaps > 0 ? 1 : 0);
