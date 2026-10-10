// The authority on a filesystem that fills up (argv[2] = a small, memory-backed folder mounted by the battery).
// A real daemon process, real ENOSPC. Counts: what the asker was told while full, whether a fragment was left,
// whether rows recorded after space returned can be read, and whether the ledger still verifies.
import { spawn } from "bun";
import { createConnection } from "net";
import { appendFileSync, existsSync, readFileSync, rmSync } from "fs";
import { join } from "path";
const dir = process.argv[2], ROOT = new URL("..", import.meta.url).pathname, CLI = join(ROOT, "src/cli/index.ts");
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const ask = (sock: string, o: object) => new Promise<any>((res) => { let b = ""; const c = createConnection(sock); c.setEncoding("utf8"); c.setTimeout(5000, () => { c.destroy(); res(null); });
  c.on("error", () => res(null)); c.on("connect", () => c.write(JSON.stringify(o) + "\n")); c.on("data", (d) => { b += d; if (b.includes("\n")) { c.destroy(); try { res(JSON.parse(b.split("\n")[0])); } catch { res(null); } } }); });
const store = join(dir, "store"), sock = join(dir, "c.sock"), ledger = join(store, "refusals.signed.jsonl");
const d = spawn([process.execPath, CLI, "approver-daemon", "--store", store, "--consume", sock, "--approve", join(dir, "a.sock"), "--source", "full"], { env: { ...process.env, HOME: dir, AEGIS_APPROVER_SUPPRESS_UID_WARN: "1" }, stdout: "ignore", stderr: "ignore" });
for (let i = 0; i < 100 && !(existsSync(sock) && (await ask(sock, { op: "ledger-status" }))?.ok); i++) await sleep(50);
const refuse = (rule: string) => ask(sock, { op: "refusal", gate: "disk-full", rule });
const before = []; for (let i = 0; i < 5; i++) before.push(await refuse(`before-${i}`));
const filler = join(dir, "filler"); try { for (;;) appendFileSync(filler, Buffer.alloc(4096, 120)); } catch {} try { for (;;) appendFileSync(filler, Buffer.alloc(64, 120)); } catch {}
const full = []; for (let i = 0; i < 12; i++) full.push(await refuse(`full-${i}`));
const whileFull = readFileSync(ledger, "utf8");
rmSync(filler); const after = []; for (let i = 0; i < 5; i++) after.push(await refuse(`after-${i}`));
const raw = readFileSync(ledger, "utf8"); const lines = raw.split("\n").filter(Boolean); let whole = 0; const seqs: number[] = [];
for (const l of lines) { try { seqs.push(JSON.parse(l).seq); whole++; } catch {} }
const v = spawn([process.execPath, CLI, "ledger-verify", ledger, "--source", "full"], { env: { ...process.env, AEGIS_LEDGER_PUBKEY_FILE: join(store, "ledger-signing.pub") }, stdout: "pipe", stderr: "pipe" });
const vOut = (await new Response(v.stdout).text()) + (await new Response(v.stderr).text()); const vCode = await v.exited; d.kill();
const acked = [...before, ...full, ...after].filter((r) => r?.ok).map((r) => r.value.seq as number);
const gaps: string[] = [];
const told = full.filter((r) => r && !r.ok).length;
if (told === 0) gaps.push("the disk never filled: the probe proved nothing");
if (!whileFull.endsWith("\n")) gaps.push("a half-written row was left in the file while the disk was full");
if (whole !== lines.length) gaps.push(`${lines.length - whole} line(s) in the ledger cannot be read`);
if (acked.some((s) => !seqs.includes(s))) gaps.push(`acknowledged row(s) ${acked.filter((s) => !seqs.includes(s)).join(", ")} cannot be read back`);
if (seqs.some((s, i) => s !== i + 1)) gaps.push("the numbering has a gap or a repeat");
if (vCode !== 0) gaps.push(`ledger-verify exit ${vCode}: ${vOut.trim().split("\n")[0].slice(0, 120)}`);
console.log(`  recorded before: ${before.filter((r) => r?.ok).length} · while full: ${full.filter((r) => r?.ok).length} recorded, ${told} refused with "${(full.find((r) => r && !r.ok)?.error || "").slice(0, 60)}" · after space returned: ${after.filter((r) => r?.ok).length}`);
console.log(`  ledger: ${lines.length} line(s), ${whole} readable, numbered 1..${seqs[seqs.length - 1]}; ledger-verify exit ${vCode}`);
for (const g of gaps) console.log(`  [GAP] ${g}`);
console.log(`\n  ledger-disk-full: ${gaps.length} gap(s)${gaps.length ? "" : " — a full disk loses the row it could not write, and nothing else ✓"}`);
process.exit(gaps.length ? 1 : 0);
