// SPDX-License-Identifier: AGPL-3.0-only
// aegis red-team — what a person approves is not what they were shown (2026-10-11, aegis 2.17.1).
// Found by reading our own approval path after Andrey Lazarev's review; not reported from outside.
//
// The destructive gate remembers a refused command under a short code; a person reads it and approves
// the code; the approval is for the SHA-256 of the whole command. Through 2.17.0:
//   - the person was shown the first 300 characters. A command whose destructive part came after the
//     300th character was approved with that part unseen;
//   - the code is the first 8 characters of the hash (32 bits), and where two waiting commands had the
//     same code the OLDER one was approved. An agent that first has a destructive command refused, then
//     a harmless one made to share its code, gets the destructive one approved by a person reading the
//     harmless one. Finding such a pair is about four thousand million hashes: minutes to an hour.
//
// GAP = an approval covers a command, or part of one, that the approving person was not shown.
// The pair with one code is NOT computed here: the store is given the two rows a collision would have
// left in it. A real approver daemon, real sockets, the real `approve-destructive` command; one user,
// so this proves the checks and not the account boundary. AEGIS_PROBE_REPO runs the same cases against
// another copy of the package. Exit: 0 all closed · 1 a gap · 3 broke.
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

const REPO = process.env.AEGIS_PROBE_REPO || new URL("..", import.meta.url).pathname;
const { startApproverDaemon } = await import(join(REPO, "src/kavach/approver-daemon.ts"));
const { hashCommand } = await import(join(REPO, "src/kavach/destructive-approval.ts"));
const client = await import(join(REPO, "src/kavach/approver-client.ts"));
const CLI = join(REPO, "src/cli/index.ts");
let gaps = 0;
const SAFE = (id: string, ok: boolean, detail: string) => { console.log(`  [${ok ? "safe" : "GAP "}] ${id} — ${detail}`); if (!ok) gaps++; };

const dir = mkdtempSync(join(tmpdir(), "aegis-approval-"));
const home = join(dir, "home"); mkdirSync(join(home, ".aegis"), { recursive: true });
const store = join(dir, "store"), consume = join(dir, "consume.sock"), approve = join(dir, "approve.sock");
const pendingFile = join(store, "destructive-pending.json");
process.env.AEGIS_APPROVER_CONSUME_SOCKET = consume; process.env.AEGIS_APPROVER_APPROVE_SOCKET = approve;
// The person, at their own terminal.
const person = async (...a: string[]): Promise<{ code: number; said: string }> => {
  const p = Bun.spawn([process.execPath, CLI, "approve-destructive", ...a], { env: { PATH: process.env.PATH || "", HOME: home, AEGIS_HOME: join(home, ".aegis"), AEGIS_APPROVER_CONSUME_SOCKET: consume, AEGIS_APPROVER_APPROVE_SOCKET: approve }, stdout: "pipe", stderr: "pipe" });
  const said = (await new Response(p.stdout).text()) + (await new Response(p.stderr).text());
  return { code: await p.exited, said };
};
const W = (...w: string[]) => w.join(" ");     // assembled from words, so this file is not itself the command
const TAIL = W("rm", "-rf", "/srv/data");

let daemon: any = null;
try {
  daemon = startApproverDaemon({ storeDir: store, consumeSocketPath: consume, approveSocketPath: approve, log: () => {} });
  await Bun.sleep(150);

  // 1. The destructive part is past what the person is shown.
  const long = `echo ${"harmless ".repeat(400)}; ${TAIL}`;
  const c1 = await client.remoteRecordPending(long, "recursive removal");
  const list1 = await person();
  const a1 = await person(c1);
  const ran1 = await client.remoteConsume(long);
  SAFE("A1 a command longer than what is shown", !list1.said.includes(TAIL) ? (a1.code !== 0 && ran1 === false) : true,
    a1.code !== 0 ? `not approved (${long.length} characters; the list says it is not the whole command: ${/NOT THE WHOLE COMMAND/.test(list1.said)})` : `APPROVED, and the gate let it run: ${ran1}. The person was shown ${list1.said.includes(TAIL) ? "" : "nothing of "}the destructive part`);
  // 1b. ...and can still approve it, by saying they read it elsewhere. That is a stated act, not a default.
  if (a1.code !== 0) {
    const c1b = await client.remoteRecordPending(long, "recursive removal");
    const a1b = await person(c1b, "--unseen-tail");
    SAFE("A1b the same, with --unseen-tail", a1b.code === 0 && (await client.remoteConsume(long)) === true, a1b.code === 0 ? "approved once the person says they read the whole command" : `exit ${a1b.code}: ${a1b.said.trim().split("\n")[0]}`);
  }
  // 2. A command the person IS shown whole needs no flag.
  const short = `psql -c "select 1"; ${TAIL}`;
  const c2 = await client.remoteRecordPending(short, "recursive removal");
  const l2 = await person(); const a2 = await person(c2);
  SAFE("A2 a command shown whole", l2.said.includes(TAIL) && a2.code === 0 && (await client.remoteConsume(short)) === true, a2.code === 0 ? "shown whole, approved, used once" : `exit ${a2.code}: ${a2.said.trim().split("\n")[0]}`);

  // 3. Two waiting commands under one code, the destructive one older (the rows a collision leaves).
  const benign = "echo tidy the build folder", evil = `${TAIL} # tidy`;
  const code = hashCommand(benign).slice(0, 8), now = Date.now();
  writeFileSync(pendingFile, JSON.stringify([
    { code, hash: hashCommand(evil), shown: evil, rule: "recursive removal", at: now - 60_000, chars: evil.length, cut: false },
    { code, hash: hashCommand(benign), shown: benign, rule: "recursive removal", at: now, chars: benign.length, cut: false },
  ]));
  const a3 = await person(code);
  const evilRuns = await client.remoteConsume(evil);
  SAFE("A3 two commands under one code", a3.code !== 0 && evilRuns === false, evilRuns ? "the person typed the code they read beside the harmless command; the OLDER, destructive one was approved and the gate let it run" : `none approved (exit ${a3.code})`);

  // 4. A new command whose code is already held by another gets a longer code of its own.
  const x = "echo rotate the logs";
  writeFileSync(pendingFile, JSON.stringify([{ code: hashCommand(x).slice(0, 8), hash: hashCommand(evil), shown: evil, rule: "recursive removal", at: Date.now(), chars: evil.length, cut: false }]));
  const c4 = await client.remoteRecordPending(x, "recursive removal");
  const a4 = await person(c4);
  const xRuns = await client.remoteConsume(x), evil4 = await client.remoteConsume(evil);
  SAFE("A4 a code already held by another command", c4.length > 8 && a4.code === 0 && xRuns === true && evil4 === false,
    c4.length > 8 ? `the new command got the code ${c4} (${c4.length} characters); approving it approved that command only` : `the new command got the same code ${c4}; approving it ${evil4 ? "approved the OTHER command" : `gave exit ${a4.code}`}`);
} catch (e) {
  console.log(`BROKE — ${(e as Error).stack || e}`); try { daemon?.stop(); } catch { /* */ } rmSync(dir, { recursive: true, force: true }); process.exit(3);
}
try { daemon?.stop(); } catch { /* */ }
rmSync(dir, { recursive: true, force: true });
console.log(`\n  approval-unseen: ${gaps} gap(s)`);
process.exit(gaps > 0 ? 1 : 0);
