// aegis red-team probe — @xshieldai/n8n-nodes, the Kavach Run node, driven outside n8n with a stand-in
// `kavachos` on PATH that records the words it was started with. Run by n8n-kavach-run.battery.sh.
const fs = require("fs"), path = require("path");
const [pkgDir, work] = process.argv.slice(2);
const { KavachRun } = require(path.join(pkgDir, "dist/nodes/KavachRun/KavachRun.node.js"));
const REC = path.join(work, "argv.json"), VER = path.join(work, "version.txt");
let cases = 0, gaps = 0;
const say = (ok, what, detail = "") => { cases++; if (!ok) gaps++; console.log(`  [${ok ? "safe" : "GAP"}] ${what}${detail ? " — " + detail : ""}`); };

async function run(params, version) {
  try { fs.unlinkSync(REC); } catch {}
  fs.writeFileSync(VER, version);
  const p = { binary: "bun", args: "", trustMask: "0xFF", domain: "general", falco: false, onNonLinux: "throw", ...params };
  const ctx = { getInputData: () => [{ json: {} }], getNodeParameter: (n) => p[n], getNode: () => ({ name: "Kavach Run", type: "kavachRun", typeVersion: 1 }) };
  let out = null, threw = null;
  try { out = await new KavachRun().execute.call(ctx); } catch (e) { threw = String(e && e.message || e); }
  const argv = fs.existsSync(REC) ? JSON.parse(fs.readFileSync(REC, "utf8")) : null;   // the words of the `run` call, or null if it was never made
  return { out, threw, argv };
}

(async () => {
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

  console.log(`\nRESULT cases=${cases} gaps=${gaps}`);
  process.exit(gaps ? 1 : 0);
})();
