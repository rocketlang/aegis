// Drives a real n8n over its own REST interface: creates credentials and workflows that use the four Kavach
// nodes, runs each, and reads the saved execution. argv: <n8n base> <cookie jar file> <aegis base> <token file> <work dir>
const http = require("http"), fs = require("fs"), path = require("path");
const [BASE, JAR, AEGIS, TOKFILE, WORK] = process.argv.slice(2);
const PKG = "@xshieldai/n8n-nodes-kavachos";
const cookie = fs.readFileSync(JAR, "utf8").split("\n").filter((l) => l && (!l.startsWith("#") || l.startsWith("#HttpOnly_"))).map((l) => l.split("\t")).filter((f) => f.length >= 7).map((f) => `${f[5]}=${f[6]}`).join("; ");
const TOKEN = fs.readFileSync(TOKFILE, "utf8").trim();

function call(method, p, body, raw) {
  return new Promise((resolve) => {
    const u = new URL(p, BASE), data = body === undefined ? null : JSON.stringify(body);
    const req = http.request(u, { method, headers: { cookie, "browser-id": "probe", ...(data ? { "content-type": "application/json", "content-length": Buffer.byteLength(data) } : {}) }, timeout: 120000 }, (res) => {
      const chunks = []; res.on("data", (c) => chunks.push(c)); res.on("end", () => { const t = Buffer.concat(chunks).toString("utf8"); let j = null; try { j = JSON.parse(t); } catch {} resolve({ status: res.statusCode, type: res.headers["content-type"] || "", json: j, text: raw ? t : t.slice(0, 600) }); });
    });
    req.on("error", (e) => resolve({ status: 0, text: String(e) })); req.on("timeout", () => req.destroy(new Error("timeout")));
    if (data) req.write(data); req.end();
  });
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let cases = 0, gaps = 0;
const say = (ok, what, detail = "") => { cases++; if (!ok) gaps++; console.log(`  [${ok ? "ok" : "GAP"}] ${what}${detail ? " — " + String(detail).replace(/\s+/g, " ").slice(0, 230) : ""}`); };

async function credential(name, baseUrl, token) {
  const r = await call("POST", "/rest/credentials", { name, type: "aegisApi", data: { baseUrl, token } });
  if (r.status !== 200) throw new Error(`credential ${name}: ${r.status} ${r.text}`);
  return { id: r.json.data.id, name };
}
// One workflow: manual trigger -> one Kavach node. Runs it and returns { status, out, error }.
async function run(label, type, parameters, cred) {
  const node = { id: "n1", name: "Kavach", type: `${PKG}.${type}`, typeVersion: 1, position: [460, 300], parameters, ...(cred ? { credentials: { aegisApi: cred } } : {}) };
  const trig = { id: "t1", name: "Start", type: "n8n-nodes-base.manualTrigger", typeVersion: 1, position: [240, 300], parameters: {} };
  const wf = { name: label, nodes: [trig, node], connections: { Start: { main: [[{ node: "Kavach", type: "main", index: 0 }]] } }, settings: {}, active: false };
  const c = await call("POST", "/rest/workflows", wf);
  if (c.status !== 200) return { status: "create-failed", error: `${c.status} ${c.text}` };
  const saved = c.json.data, t0 = Date.now();
  const r = await call("POST", `/rest/workflows/${saved.id}/run`, { workflowData: saved, triggerToStartFrom: { name: "Start" } });
  const id = r.json?.data?.executionId;
  if (!id) return { status: "run-failed", error: `${r.status} ${r.text}` };
  for (let i = 0; i < 240; i++) {
    await sleep(500);
    const e = await call("GET", `/rest/executions/${id}`, undefined, true);
    const d = e.json?.data; if (!d || !d.finished && !d.stoppedAt) continue;
    // n8n stores run data flattened (an array with index references); let it be parsed by walking.
    let data = d.data; if (typeof data === "string") { const flat = JSON.parse(data); const seen = new Map(); const un = (v) => { if (typeof v === "string" && /^\d+$/.test(v) && flat[+v] !== undefined) return res(+v); return v; }; const res = (i2) => { if (seen.has(i2)) return seen.get(i2); const v = flat[i2]; if (v === null || typeof v !== "object") return v; const o = Array.isArray(v) ? [] : {}; seen.set(i2, o); for (const k of Object.keys(v)) o[k] = un(v[k]); return o; }; data = res(0); }
    const rd = data?.resultData || {}, last = rd.runData?.Kavach?.[0];
    return { status: d.status, ms: Date.now() - t0, out: last?.data?.main?.[0]?.[0]?.json, error: (last?.error || rd.error)?.message, description: (last?.error || rd.error)?.description };
  }
  return { status: "never-finished" };
}

(async () => {
  // ── what n8n knows about the package ──
  const pk = await call("GET", "/rest/community-packages");
  const mine = (pk.json?.data || []).find((p) => p.packageName === PKG);
  say(!!mine && mine.installedNodes.length === 4, "n8n lists the package as installed, with four nodes", mine ? `${mine.installedVersion}: ${mine.installedNodes.map((n) => n.name).join(", ")}` : pk.text);
  const types = await call("GET", "/types/nodes.json", undefined, true);
  const known = (types.json || []).filter((t) => String(t.name).startsWith(PKG + "."));
  say(known.length === 4, "the editor's node list holds the four node types", known.map((t) => t.name.split(".").pop()).join(", ") || `${types.status}`);
  for (const t of known) {
    const iconUrl = t.iconUrl && (typeof t.iconUrl === "string" ? t.iconUrl : t.iconUrl.light);
    const ic = iconUrl ? await call("GET", "/" + iconUrl.replace(/^\//, ""), undefined, true) : { status: 0, text: "" };
    say(ic.status === 200 && /<svg[\s>]/.test(ic.text), `n8n serves the icon of ${t.displayName}`, `${iconUrl || "no icon address"} → ${ic.status} ${ic.type}`);
  }
  const ct = await call("GET", "/types/credentials.json", undefined, true);
  say((ct.json || []).some((c) => c.name === "aegisApi"), "the credential type Aegis API is offered");

  const withToken = await credential("Aegis (token)", AEGIS, TOKEN), noToken = await credential("Aegis (no token)", AEGIS, ""), dead = await credential("Aegis (not there)", "http://127.0.0.1:9", "");

  // ── Kavach Gate against a real Aegis ──
  let r = await run("gate safe", "kavachGate", { command: "echo hello", toolName: "n8n-live", sessionId: "live-1", dryRun: false, timeoutSeconds: 30, onBlock: "throw" }, noToken);
  say(r.status === "success" && r.out?.kavach?.allow === true, "Gate: a harmless command is allowed and the workflow goes on", JSON.stringify(r.out?.kavach ?? r));
  r = await run("gate dangerous continue", "kavachGate", { command: "rm -rf /", toolName: "n8n-live", sessionId: "live-2", dryRun: true, timeoutSeconds: 30, onBlock: "continue" }, noToken);
  say(r.status === "success" && r.out?.kavach?.allow === false && r.out?.kavach?.level >= 1, "Gate: a dangerous command (dry run, continue) comes out as allow=false with its level", JSON.stringify(r.out?.kavach ?? r));
  r = await run("gate dangerous throw", "kavachGate", { command: "rm -rf /", toolName: "n8n-live", sessionId: "live-3", dryRun: true, timeoutSeconds: 30, onBlock: "throw" }, noToken);
  say(r.status === "error" && !!r.error, "Gate: a dangerous command (dry run, throw) stops the workflow with an error", r.error || JSON.stringify(r));
  r = await run("gate unreachable", "kavachGate", { command: "echo hello", toolName: "n8n-live", sessionId: "live-4", dryRun: false, timeoutSeconds: 10, onBlock: "throw" }, dead);
  say(r.status === "error" && !/allow/i.test(JSON.stringify(r.out || "")), "Gate: an Aegis that is not there stops the workflow; nothing is allowed", r.error || JSON.stringify(r));
  r = await run("gate unreachable continue", "kavachGate", { command: "echo hello", toolName: "n8n-live", sessionId: "live-5", dryRun: false, timeoutSeconds: 10, onBlock: "continue" }, dead);
  say(r.out?.kavach?.allow !== true, "Gate: an Aegis that is not there never comes out as allow=true, even on 'continue'", r.error || JSON.stringify(r.out?.kavach ?? r));

  // ── Kavach Run with the stand-in kavachos ──
  // The stand-in runs as the container's user: the file must be readable by it whatever this shell's umask is.
  const mode = (m) => { const f = path.join(WORK, "mode.txt"); fs.writeFileSync(f, m); fs.chmodSync(f, 0o644); };
  const runParams = (extra = {}) => ({ binary: "echo", args: "--domain=evil -x 'two words'", trustMask: "0xFF", domain: "general", falco: false, timeoutSeconds: 30, onNonLinux: "throw", ...extra });
  mode("ok"); try { fs.unlinkSync(path.join(WORK, "argv.json")); } catch {}
  r = await run("run ok", "kavachRun", runParams());
  let argv = []; try { argv = JSON.parse(fs.readFileSync(path.join(WORK, "argv.json"), "utf8")); } catch {}
  const sep = argv.indexOf("--");
  say(r.status === "success" && sep > 0 && JSON.stringify(argv.slice(sep + 1)) === JSON.stringify(["echo", "--domain=evil", "-x", "'two", "words'"]), "Run: the binary's arguments reach kavachos after `--`, split on spaces as the field says (quotes are not read)", JSON.stringify(argv));
  say(r.out?.kavach_run?.enforced === true, "Run: a launch kavachos did not complain about is reported enforced", JSON.stringify(r.out?.kavach_run ?? r).slice(0, 200));
  mode("unconstrained"); r = await run("run unconstrained", "kavachRun", runParams());
  say(r.status === "success" && r.out?.kavach_run?.enforced === false && r.out?.kavach_run?.egress_constrained === false, "Run: a launch kavachos called not egress-constrained is NOT reported enforced", JSON.stringify(r.out?.kavach_run ?? r).slice(0, 200));
  mode("refuse"); r = await run("run refused", "kavachRun", runParams());
  say(r.status === "error" && /refus/i.test(r.error || ""), "Run: a launch kavachos refused stops the workflow with an error", r.error || JSON.stringify(r));
  mode("sleep");
  const slow = run("run sleep", "kavachRun", runParams({ timeoutSeconds: 4 }));
  await sleep(1500); const t0 = Date.now(); const h = await call("GET", "/healthz"); const lag = Date.now() - t0;
  say(h.status === 200 && lag < 1000, "Run: while a command is running, n8n still answers", `healthz ${h.status} in ${lag} ms`);
  r = await slow;
  say(r.status === "error" && /time limit|stopped after/i.test(r.error || "") && r.ms < 20000, "Run: a command that does not end is stopped at the node's time limit", `${r.error} (${r.ms} ms)`);
  mode("ok");

  // ── Kavach Budget and Kavach Audit against the real Aegis ──
  r = await run("budget", "kavachBudget", { haltOnBreach: false }, noToken);
  say(r.status === "success" && r.out && typeof r.out === "object", "Budget: the node reads the budget state from Aegis", JSON.stringify(r.out ?? r).slice(0, 200));
  r = await run("audit token", "kavachAudit", { sessionId: "", status: "all", danLevel: 0, limit: 5 }, withToken);
  say(r.status === "success", "Audit: with the adapters' token the node reads the gate audit", JSON.stringify(r.out ?? r).slice(0, 200));
  r = await run("audit no token", "kavachAudit", { sessionId: "", status: "all", danLevel: 0, limit: 5 }, noToken);
  say(r.status === "error" && /401|auth|session|token/i.test((r.error || "") + (r.description || "")), "Audit: without a token the node is refused, and says so", `${r.error} ${r.description || ""}`);

  console.log(`\nRESULT cases=${cases} gaps=${gaps}`);
  process.exit(gaps ? 1 : 0);
})().catch((e) => { console.log("BROKE — " + (e.stack || e)); process.exit(3); });
