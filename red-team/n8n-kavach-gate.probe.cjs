// aegis red-team probe — @xshieldai/n8n-nodes-kavachos, the Kavach Gate node, driven outside n8n against a stand-in
// gate on 127.0.0.1 that answers as each case says. Run by n8n-kavach-run.battery.sh.
const http = require("http"), path = require("path");
const [pkgDir] = process.argv.slice(2);
const { KavachGate } = require(path.join(pkgDir, "dist/nodes/KavachGate/KavachGate.node.js"));
let cases = 0, gaps = 0, answer = null;
const say = (ok, what, detail = "") => { cases++; if (!ok) gaps++; console.log(`  [${ok ? "safe" : "GAP"}] ${what}${detail ? " — " + detail : ""}`); };
const server = http.createServer((req, res) => { let b = ""; req.on("data", (d) => (b += d)); req.on("end", () => answer(req, res, b)); });

async function gate(params, base) {
  const p = { command: "rm -rf build", toolName: "probe", sessionId: "s1", dryRun: false, onBlock: "throw", timeoutSeconds: 660, ...params };
  const ctx = { getInputData: () => [{ json: {} }], getNodeParameter: (n, _i, d) => (n in p ? p[n] : d), getNode: () => ({ name: "Kavach Gate", type: "kavachGate", typeVersion: 1 }),
                getCredentials: async () => ({ baseUrl: base, token: "" }) };
  const t0 = Date.now(); let out = null, threw = null;
  try { out = await new KavachGate().execute.call(ctx); } catch (e) { threw = String(e && e.message || e); }
  // "Passed" is what the workflow would do next. In throw mode, returning at all means it goes on. In continue
  // mode the next node reads kavach.allow, and anything but the boolean false reads as a yes to an IF node.
  const k = out ? out[0][0].json.kavach : null;
  return { passed: out !== null && (p.onBlock === "throw" || k.allow !== false), threw, ms: Date.now() - t0, k };
}
const json = (o, status = 200) => (_req, res) => { res.writeHead(status, { "Content-Type": "application/json" }); res.end(JSON.stringify(o)); };

server.listen(0, "127.0.0.1", async () => {
  const base = `http://127.0.0.1:${server.address().port}`;
  let r;
  answer = json({ allow: true, level: 0, reason: "no dangerous patterns found" });
  r = await gate({}, base); say(r.passed, "control: the gate's allow lets the workflow on", r.threw || "passed");
  answer = json({ allow: false, level: 3, reason: "irreversible" });
  r = await gate({}, base); say(!r.passed && /blocked/.test(r.threw || ""), "control: the gate's stop halts the workflow", (r.threw || "passed").slice(0, 60));

  for (const [name, body] of [['the text "false"', { allow: "false", reason: "x" }], ['the text "no"', { allow: "no", reason: "x" }], ["the number 1", { allow: 1, reason: "x" }], ["an object", { allow: {}, reason: "x" }]]) {
    answer = json(body);
    r = await gate({}, base); say(!r.passed, `an answer whose allow is ${name} is not an allow`, r.passed ? "the workflow went on" : (r.threw || "").slice(0, 70));
    r = await gate({ onBlock: "continue" }, base); say(!r.passed, `… nor in "continue" mode`, r.passed ? `passed downstream as allow=${JSON.stringify(r.k && r.k.allow)}` : (r.threw ? r.threw.slice(0, 50) : `allow ${r.k && r.k.allow}`));
  }
  answer = json({ status: "ok", service: "something-else" });
  r = await gate({}, base); say(!r.passed, "an answer with no allow at all (some other service) is not an allow", (r.threw || "passed").slice(0, 80));

  answer = (_q, res) => { res.writeHead(500, { "Content-Type": "application/json" }); res.end('{"error":"boom"}'); };
  r = await gate({}, base); say(!r.passed && /HTTP 500/.test(r.threw || "") && !/Cannot reach/.test(r.threw || ""), "a server error is reported as a server error, not as 'cannot reach'", (r.threw || "").slice(0, 80));
  answer = (_q, res) => { res.writeHead(302, { Location: `${base}/elsewhere` }); res.end(); };
  r = await gate({}, base); say(!r.passed && /302/.test(r.threw || ""), "a redirect is not followed and is not a decision", (r.threw || "passed").slice(0, 70));

  answer = (_q, res) => { setTimeout(() => { res.writeHead(200, { "Content-Type": "application/json" }); res.end('{"allow":true,"reason":"late"}'); }, 6000); };
  r = await gate({ timeoutSeconds: 2 }, base); say(!r.passed && r.ms < 5000 && /within 2 s|no decision/.test(r.threw || ""), "no decision within the node's own time limit is a block", `${(r.threw || "passed").slice(0, 70)} (${r.ms} ms)`);
  r = await gate({ timeoutSeconds: 2, onBlock: "continue" }, base); say(!r.passed && r.k && r.k.allow === false && r.k.decision === "TIMEOUT", `… and in "continue" mode it goes downstream as allow=false, decision TIMEOUT`, r.k ? `allow ${r.k.allow}, decision ${r.k.decision}` : r.threw);
  r = await gate({}, "http://127.0.0.1:9"); say(!r.passed && /Cannot reach|refused the connection|offline/.test(r.threw || ""), "an Aegis that is not there is reported as not reachable", (r.threw || "").slice(0, 60));

  server.close();
  console.log(`\nRESULT cases=${cases} gaps=${gaps}`);
  process.exit(gaps ? 1 : 0);
});
