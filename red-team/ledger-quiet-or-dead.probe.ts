// SPDX-License-Identifier: AGPL-3.0-only
// aegis red-team — a quiet ledger or a dead authority? (2026-10-11, aegis 2.17.0)
// Pointed out by Andrey Lazarev against 2.16.2: the anchor statement carried no time, so a ledger that had not
// grown added no leaf, and someone reading the public log could not tell a week with no refusals from an
// authority switched off a week ago.
//
// Now an anchor can be dated (`aegis ledger-anchor --dated`), one leaf a day. This drives real processes
// against a stand-in log with three cosigning witnesses, with the authority's clock and the witnesses' clock
// set by the probe, and asks `aegis ledger-verify` (which reads the real clock) what it sees:
//   - a quiet week, one dated leaf a day, the last one yesterday            → clean, and it says so
//   - undated anchors made before the switch                                → still verify
//   - a second run on the same day, the ledger grown                        → no second leaf
//   - a file cut back below a dated leaf                                    → TRUNCATION OR REWRITE, exit 1
//   - the receipts lost                                                     → UNVERIFIABLE as to time, exit 2
//   - an authority stopped three days ago                                   → SILENT SINCE, the days named, exit 1
//   - one missed day, then back                                             → UNVERIFIABLE for that day, exit 2;
//                                                                             named as known by a person: clean
//   - the dead days signed afterwards with the clock put back               → DAY FILLED IN LATE, exit 1
//   - a day signed for after a later day is already in the log              → DAY FILLED IN LATE, exit 1
//   - a statement for a day that has not come                               → DATED IN THE FUTURE, exit 1
//
// GAP = silence, a late day or a future day reads as clean. On 2.16.3 every case but the cut-back file is a gap.
// The log is a stand-in written from the protocol: this proves the verifier's reading, nothing about a real log.
// One user throughout: not the uid boundary. A run that straddles midnight UTC can miscount a day; run it again.
// Exit: 0 all closed · 1 a gap · 3 broke.
import { createHash, generateKeyPairSync, sign, verify, randomBytes, createPublicKey } from "crypto";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { startApproverDaemon } from "../src/kavach/approver-daemon.ts";

const REPO = new URL("..", import.meta.url).pathname;
const SOURCE = "probe-box";
let gaps = 0;
const SAFE = (id: string, ok: boolean, detail: string) => { console.log(`  [${ok ? "safe" : "GAP "}] ${id} — ${detail}`); if (!ok) gaps++; };
const sha = (...b: Uint8Array[]) => { const h = createHash("sha256"); b.forEach((x) => h.update(x)); return h.digest(); };
const rawPub = (k: ReturnType<typeof createPublicKey>) => Buffer.from(k.export({ format: "der", type: "spki" })).subarray(-32);
const DAY = 86_400_000;
const today = new Date(); const noon = (offset: number) => new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate(), 12) + offset * DAY);
const dayOf = (offset: number) => noon(offset).toISOString().slice(0, 10);

// ── a stand-in log (sigsum log.md), with witnesses whose clock the probe sets ───────────────────
type Leaf = [checksum: string, signature: string, keyHash: string];
const mth = (d: Buffer[]): Buffer => { if (d.length === 0) return sha(); if (d.length === 1) return d[0]; let k = 1; while (k * 2 < d.length) k *= 2; return sha(Buffer.from([1]), mth(d.slice(0, k)), mth(d.slice(k))); };
const auditPath = (m: number, d: Buffer[]): Buffer[] => { if (d.length <= 1) return []; let k = 1; while (k * 2 < d.length) k *= 2; return m < k ? [...auditPath(m, d.slice(0, k)), mth(d.slice(k))] : [...auditPath(m - k, d.slice(k)), mth(d.slice(0, k))]; };
function standInLog() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519"); const key = rawPub(publicKey);
  const witnesses = [1, 2, 3].map((i) => { const kp = generateKeyPairSync("ed25519"); return { name: `w${i}`, key: rawPub(kp.publicKey).toString("hex"), priv: kp.privateKey }; });
  const leaves: Leaf[] = []; const seenOnce = new Set<string>(); const clock = { at: new Date() };
  const lh = (l: Leaf) => sha(Buffer.from([0]), Buffer.from(l[0], "hex"), Buffer.from(l[1], "hex"), Buffer.from(l[2], "hex"));
  const foreign = (): Leaf => [randomBytes(32).toString("hex"), randomBytes(64).toString("hex"), randomBytes(32).toString("hex")];
  for (let i = 0; i < 3; i++) leaves.push(foreign());
  const server = Bun.serve({ port: 0, hostname: "127.0.0.1", async fetch(req) {
    const path = new URL(req.url).pathname; const text = (s: string, status = 200) => new Response(s, { status });
    if (path === "/get-tree-head") {
      const root = mth(leaves.map(lh)); const signed = `sigsum.org/v1/tree/${sha(key).toString("hex")}\n${leaves.length}\n${root.toString("base64")}\n`;
      const ts = Math.floor(clock.at.getTime() / 1000);
      const cos = witnesses.map((w) => `cosignature=${sha(Buffer.from(w.key, "hex")).toString("hex")} ${ts} ${sign(null, Buffer.from(`cosignature/v1\ntime ${ts}\n${signed}`), w.priv).toString("hex")}\n`).join("");
      return text(`size=${leaves.length}\nroot_hash=${root.toString("hex")}\nsignature=${sign(null, Buffer.from(signed), privateKey).toString("hex")}\n${cos}`);
    }
    if (path === "/add-leaf" && req.method === "POST") {
      const f = Object.fromEntries((await req.text()).split("\n").filter(Boolean).map((l) => l.split("=")));
      const checksum = sha(Buffer.from(f.message, "hex")); const pub = Buffer.from(f.public_key, "hex");
      if (!verify(null, Buffer.concat([Buffer.from("sigsum.org/v1/tree-leaf\0"), checksum]), createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), pub]), format: "der", type: "spki" }), Buffer.from(f.signature, "hex"))) return text("(403) bad leaf signature\n", 403);
      const leaf: Leaf = [checksum.toString("hex"), f.signature, sha(pub).toString("hex")]; const id = leaf.join(" ");
      if (leaves.some((l) => l.join(" ") === id)) return text("", 200);
      if (!seenOnce.has(id)) { seenOnce.add(id); return text("(202) Accepted\n", 202); }
      leaves.push(leaf); leaves.push(foreign()); return text("", 200);
    }
    let m = path.match(/^\/get-inclusion-proof\/(\d+)\/([0-9a-f]{64})$/);
    if (m) { const hashes = leaves.slice(0, Number(m[1])).map(lh); const i = hashes.findIndex((h) => h.toString("hex") === m![2]); if (i < 0) return text("(404) not found\n", 404); return text(`leaf_index=${i}\n` + auditPath(i, hashes).map((h) => `node_hash=${h.toString("hex")}\n`).join("")); }
    m = path.match(/^\/get-leaves\/(\d+)\/(\d+)$/);
    if (m) { const from = Number(m[1]), to = Math.min(Number(m[2]), from + 50, leaves.length); return text(leaves.slice(from, to).map((l) => `leaf=${l.join(" ")}\n`).join("")); }
    return text("(404)\n", 404);
  } });
  return { url: `http://127.0.0.1:${server.port}`, key: key.toString("hex"), leaves, witnesses, clock, stop: () => server.stop(true) };
}

// ── one rig: an authority with a clock, a log with a clock, the real CLI ────────────────────────
const top = mkdtempSync(join(tmpdir(), "aegis-quiet-or-dead-"));
const aegisDirBefore = process.env.AEGIS_DIR;
let rigN = 0;
async function rig() {
  const dir = join(top, `rig-${++rigN}`); const store = join(dir, "store"), home = join(dir, "home"), sock = join(dir, "consume.sock");
  mkdirSync(home, { recursive: true });
  const clock = { at: new Date() };
  const daemon = startApproverDaemon({ storeDir: store, consumeSocketPath: sock, approveSocketPath: join(dir, "approve.sock"), ledgerSource: SOURCE, log: () => {}, ledgerNow: () => clock.at } as Parameters<typeof startApproverDaemon>[0]);
  const log = standInLog();
  for (let i = 0; i < 50 && !existsSync(sock); i++) await new Promise((r) => setTimeout(r, 50));
  const pubFile = join(store, "ledger-signing.pub"), ledgerFile = join(store, "refusals.signed.jsonl"), receipts = join(home, "ledger-anchors.jsonl"), policyFile = join(dir, "two-of-three.policy");
  writeFileSync(policyFile, `log ${log.key} ${log.url}\n` + log.witnesses.map((w) => `witness ${w.name} ${w.key}\n`).join("") + "group g 2 w1 w2 w3\nquorum g\n");
  const cli = async (args: string[]) => {
    const p = Bun.spawn([process.execPath, join(REPO, "src/cli/index.ts"), ...args], { env: { PATH: process.env.PATH || "", HOME: home, AEGIS_HOME: home, AEGIS_LEDGER_PUBKEY_FILE: pubFile, AEGIS_ANCHOR_WAIT_MS: "30" }, stdout: "pipe", stderr: "pipe" });
    const [out, err, code] = await Promise.all([new Response(p.stdout).text(), new Response(p.stderr).text(), p.exited]);
    return { code, out: out + err };
  };
  const kh = () => sha(rawPub(createPublicKey(readFileSync(pubFile, "utf-8")))).toString("hex");
  return {
    dir, ledgerFile, receipts,
    /** Set both clocks to noon (UTC) of today+offset. `logOffset` sets the witnesses' clock apart. */
    at(offset: number, logOffset = offset) { clock.at = noon(offset); log.clock.at = noon(logOffset); },
    refuse: (rule: string) => daemon.ledger.record({ gate: "probe-gate", rule }),
    anchor: (extra: string[] = ["--dated"]) => cli(["ledger-anchor", "--log", log.url, "--log-key", log.key, "--socket", sock, "--receipts", receipts, "--policy", policyFile, ...extra]),
    verify: (file = ledgerFile, extra: string[] = []) => cli(["ledger-verify", file, "--source", SOURCE, "--anchor-log", log.url, "--anchor-log-key", log.key, "--anchor-policy", policyFile, "--receipts", receipts, ...extra]),
    ours: () => log.leaves.filter((l) => l[2] === kh()).length,
    stop() { daemon.stop(); log.stop(); },
  };
}
const brief = (s: string) => (s.split("\n").find((l) => /SILENT|UNVERIFIABLE|LATE|FUTURE|TRUNCATION|dated anchors/.test(l)) || s.split("\n")[0] || "").replace("[ledger-verify] ", "").slice(0, 150);

try {
  // ── a quiet week after an undated start ────────────────────────────────────────────────────
  let r = await rig();
  r.at(-7); r.refuse("R-1"); r.refuse("R-2"); await r.anchor([]);            // the old way, before the switch
  for (const d of [-5, -4, -3, -2, -1]) { r.at(d); if (d === -3) r.refuse("R-3"); await r.anchor(); }
  let v = await r.verify();
  SAFE("a quiet week, one dated leaf a day, reads clean and says so", v.code === 0 && v.out.includes("dated anchors: 5 leaf(s)") && v.out.includes(`from ${dayOf(-5)} to ${dayOf(-1)}`) && r.ours() === 6,
    `exit ${v.code}; ${r.ours()} leaves of ours in the log; ${brief(v.out)}`);
  SAFE("each dated leaf is shown in the log on its own day by the witnesses' signatures", v.out.includes("5 dated leaf(s) were in the log on their own day"), brief(v.out.split("\n").filter((l) => l.includes("own day")).join("\n") || "no such line"));
  r.refuse("R-4"); const again = await r.anchor();
  SAFE("a second run on the same day sends no second leaf, though the ledger has grown", again.code === 0 && again.out.includes("One leaf a day") && r.ours() === 6, `exit ${again.code}; ${r.ours()} leaves`);
  const cut = join(r.dir, "cut.jsonl"); writeFileSync(cut, readFileSync(r.ledgerFile, "utf-8").split("\n").filter(Boolean).slice(0, 2).join("\n") + "\n");
  v = await r.verify(cut);
  SAFE("control: a file cut back below a dated leaf is still TRUNCATION OR REWRITE", v.code === 1 && v.out.includes("TRUNCATION OR REWRITE"), `exit ${v.code}; ${brief(v.out)}`);
  writeFileSync(r.receipts, "");
  v = await r.verify();
  SAFE("with the receipts lost, the days are the key holder's word and it says so", v.code === 2 && v.out.includes("UNVERIFIABLE as to time"), `exit ${v.code}; ${brief(v.out)}`);
  r.stop();

  // ── an authority stopped three days ago ────────────────────────────────────────────────────
  r = await rig();
  r.at(-6); r.refuse("R-1");
  for (const d of [-6, -5, -4]) { r.at(d); await r.anchor(); }
  v = await r.verify();
  SAFE("an authority stopped three days ago is named, day by day", v.code === 1 && v.out.includes(`SILENT SINCE ${dayOf(-4)}`) && [-3, -2, -1].every((d) => v.out.includes(dayOf(d))),
    `exit ${v.code}; ${brief(v.out)}`);

  // ── …and the dead days signed afterwards, with the authority's clock put back ───────────────
  for (const d of [-3, -2, -1]) { r.at(d, 0); await r.anchor(); }           // the witnesses' clock is today
  v = await r.verify();
  SAFE("dead days signed afterwards are DAY FILLED IN LATE: the witnesses saw them today", v.code === 1 && v.out.includes("DAY FILLED IN LATE") && v.out.includes(dayOf(-3)), `exit ${v.code}; ${brief(v.out)}`);
  r.stop();

  // ── one missed day, then back ──────────────────────────────────────────────────────────────
  r = await rig();
  r.at(-5); r.refuse("R-1");
  for (const d of [-5, -4, -2, -1]) { r.at(d); await r.anchor(); }
  v = await r.verify();
  SAFE("one missed day is named, and is not clean", v.code === 2 && v.out.includes("UNVERIFIABLE for 1 day(s)") && v.out.includes(dayOf(-3)), `exit ${v.code}; ${brief(v.out)}`);
  v = await r.verify(r.ledgerFile, ["--anchor-known-holes", dayOf(-3)]);
  SAFE("the same day, named as known by a person, no longer fails the check and is still printed", v.code === 0 && v.out.includes(`no dated anchor for ${dayOf(-3)}`), `exit ${v.code}`);
  // a day signed for after a later day is already in the log
  r.at(-3); await r.anchor();
  v = await r.verify();
  SAFE("a day signed for after a later day is in the log is DAY FILLED IN LATE", v.code === 1 && v.out.includes("AFTER a leaf for a later day"), `exit ${v.code}; ${brief(v.out)}`);
  r.stop();

  // ── a day that has not come ────────────────────────────────────────────────────────────────
  r = await rig();
  r.at(-2); r.refuse("R-1");
  for (const d of [-2, -1]) { r.at(d); await r.anchor(); }
  r.at(3, 0); await r.anchor();
  v = await r.verify();
  SAFE("a statement for a day that has not come is DATED IN THE FUTURE", v.code === 1 && v.out.includes("DATED IN THE FUTURE") && v.out.includes(dayOf(3)), `exit ${v.code}; ${brief(v.out)}`);
  r.stop();
} catch (e) {
  console.log(`BROKE — ${(e as Error).message}`); process.exitCode = 3;
} finally {
  if (aegisDirBefore === undefined) delete process.env.AEGIS_DIR; else process.env.AEGIS_DIR = aegisDirBefore;
  try { rmSync(top, { recursive: true, force: true }); } catch { /* */ }
}
if (process.exitCode === 3) process.exit(3);
console.log(gaps === 0 ? "\nAll closed." : `\n${gaps} gap(s).`);
process.exit(gaps === 0 ? 0 : 1);
