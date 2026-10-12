// aegis red-team probe — @xshieldai/n8n-nodes-kavachos, the Kavach Run node, driven outside n8n with a stand-in
// `kavachos` on PATH. The stand-in records the words it was started with and then behaves as the file
// mode.txt says. Run by n8n-kavach-run.battery.sh.
const fs = require("fs"), path = require("path");
const [pkgDir, work] = process.argv.slice(2);
const { KavachRun } = require(path.join(pkgDir, "dist/nodes/KavachRun/KavachRun.node.js"));
const REC = path.join(work, "argv.json"), VER = path.join(work, "version.txt"), MODE = path.join(work, "mode.txt");
let cases = 0, gaps = 0;
const say = (ok, what, detail = "") => { cases++; if (!ok) gaps++; console.log(`  [${ok ? "safe" : "GAP"}] ${what}${detail ? " — " + detail : ""}`); };

async function run(params, version, mode = "ok") {
  try { fs.unlinkSync(REC); } catch {}
  fs.writeFileSync(VER, version); fs.writeFileSync(MODE, mode);
  const p = { binary: "bun", args: "", trustMask: "0xFF", domain: "general", falco: false, onNonLinux: "throw", timeoutSeconds: 300, ...params };
  const ctx = { getInputData: () => [{ json: {} }], getNodeParameter: (n, _i, d) => (n in p ? p[n] : d), getNode: () => ({ name: "Kavach Run", type: "kavachRun", typeVersion: 1 }) };
  let out = null, threw = null, ticks = 0;
  const t0 = Date.now(), beat = setInterval(() => { ticks++; }, 50);   // does anything else get to run meanwhile?
  try { out = await new KavachRun().execute.call(ctx); } catch (e) { threw = String(e && e.message || e); }
  clearInterval(beat);
  const argv = fs.existsSync(REC) ? JSON.parse(fs.readFileSync(REC, "utf8")) : null;
  return { out, threw, argv, ticks, ms: Date.now() - t0, kr: out ? out[0][0].json.kavach_run : null };
}

(async () => {
  // ── the binary's arguments are arguments (1.3.0) ──
  let r = await run({ args: "agent.ts --port 4900 --dry-run --allow-unconstrained-egress" }, "2.5.0");
  const want = ["run", "--trust-mask=0xFF", "--domain=general", "--", "bun", "agent.ts", "--port", "4900", "--dry-run", "--allow-unconstrained-egress"];
  say(JSON.stringify(r.argv) === JSON.stringify(want), "the binary and its arguments go after a bare --, word for word", JSON.stringify(r.argv));
  r = await run({ binary: "--dry-run", args: "x" }, "2.5.0");
  const sep = r.argv ? r.argv.indexOf("--") : -1;
  say(sep !== -1 && r.argv.indexOf("--dry-run") > sep, "a binary named like an option still stands after the --", JSON.stringify(r.argv));
  r = await run({ args: "agent.ts --dry-run" }, "2.4.0");
  say(r.threw !== null && r.argv === null, "with a kavachos that does not read -- (2.4.0) the node refuses and runs nothing", r.threw ? r.threw.slice(0, 90) : `it ran: ${JSON.stringify(r.argv)}`);
  r = await run({ args: "agent.ts" }, "not-a-version");
  say(r.threw !== null && r.argv === null, "with a kavachos whose version cannot be read the node refuses", r.threw ? r.threw.slice(0, 70) : "it ran");
  r = await run({ args: "agent.ts", falco: true }, "2.6.1");
  say(r.argv && r.argv.indexOf("--falco") !== -1 && r.argv.indexOf("--falco") < r.argv.indexOf("--"), "the node's own options stay before the --", JSON.stringify(r.argv));
  // 1.5.2: quotes group. Through 1.5.1 the field was cut at every space.
  r = await run({ binary: "echo", args: `--name 'two words' --k="a b" plain` }, "2.6.1");
  say(r.argv && JSON.stringify(r.argv.slice(r.argv.indexOf("--") + 1)) === JSON.stringify(["echo", "--name", "two words", "--k=a b", "plain"]), "an argument in quotes reaches kavachos as one word", JSON.stringify(r.argv));
  r = await run({ binary: "echo", args: "$HOME * ~ C:\\dir ; rm" }, "2.6.1");
  say(r.argv && JSON.stringify(r.argv.slice(r.argv.indexOf("--") + 1)) === JSON.stringify(["echo", "$HOME", "*", "~", "C:\\dir", ";", "rm"]), "nothing else is read specially: $, *, ~, a backslash and ; stay as written", JSON.stringify(r.argv));
  r = await run({ binary: "echo", args: "--name 'never closed" }, "2.6.1");
  say(r.threw !== null && r.argv === null, "a quote that is never closed is refused and nothing is run", r.threw ? r.threw.slice(0, 90) : `it ran: ${JSON.stringify(r.argv)}`);

  // ── what the node says happened is what kavachos said happened (1.4.0) ──
  r = await run({ args: "agent.ts" }, "2.6.0", "ok");
  say(r.kr && r.kr.enforced === true && r.kr.exit_code === 0, "control: a clean launch is reported as enforced", r.kr ? `enforced ${r.kr.enforced}, exit ${r.kr.exit_code}` : r.threw);
  r = await run({ args: "agent.ts" }, "2.6.0", "refuse");
  say(r.threw !== null && /refused/.test(r.threw), "a launch kavachos REFUSED is an error, not an enforced run", r.threw ? r.threw.slice(0, 80) : `returned: enforced ${r.kr && r.kr.enforced}, exit ${r.kr && r.kr.exit_code}`);
  r = await run({ args: "agent.ts" }, "2.6.0", "unconstrained");
  say(r.kr && r.kr.enforced === false && r.kr.egress_constrained === false, "a launch kavachos said was NOT egress-constrained is not reported as enforced", r.kr ? `enforced ${r.kr.enforced}, egress_constrained ${r.kr.egress_constrained}` : r.threw);
  r = await run({ args: "agent.ts" }, "2.6.0", "agent-exit-3");
  say(r.kr && r.kr.exit_code === 3 && r.threw === null, "the command's own exit status 3 is passed on, not mistaken for a refusal", r.kr ? `exit ${r.kr.exit_code}` : r.threw);

  // ── a long command neither stops n8n nor runs for ever (1.4.0) ──
  r = await run({ args: "agent.ts", timeoutSeconds: 2 }, "2.6.0", "sleep");
  say(r.threw !== null && /time limit|stopped/.test(r.threw) && r.ms < 8000, "a command that outlasts the time limit is stopped and the node fails", r.threw ? `${r.threw.slice(0, 60)} (${r.ms} ms)` : `returned after ${r.ms} ms: exit ${r.kr && r.kr.exit_code}`);
  say(r.ticks >= 10, "while the command runs, the rest of n8n keeps running", `${r.ticks} timer ticks in ${r.ms} ms`);
  r = await run({ args: "agent.ts" }, "2.6.0", "bigout");
  say(r.kr && r.kr.output_truncated === true && r.kr.exit_code === 0, "output beyond the cap is cut and said to be cut; the command is not killed", r.kr ? `truncated ${r.kr.output_truncated}, exit ${r.kr.exit_code}, kept ${r.kr.stdout.length} bytes` : r.threw);

  console.log(`\nRESULT cases=${cases} gaps=${gaps}`);
  process.exit(gaps ? 1 : 0);
})();
