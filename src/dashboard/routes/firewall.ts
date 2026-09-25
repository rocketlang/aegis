// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.
//
// Firewall Cockpit (AF-T-802 / FP-015): the founder-facing projection of the Agent
// Firewall's witness-and-decide functions. Every action here calls the SAME code the
// CLI faces run (touched aggregation, tripwire stage/clear, sealed mode, publish
// mandates) — the page is a projection, never a second implementation (FP-016).
//
// Deliberately BEHIND the session guard (not in the public pass-through): clearing
// evidence, flipping the containment mode, and granting publish mandates are founder
// decisions. The mode flip requires typing the mode back (named-consent style, CA-002).

import type { FastifyInstance } from "fastify";
import { readFileSync, existsSync } from "fs";
import { join } from "path";
import { aggregateTouched, parseSince } from "../../kavach/touched";
import { stageFor, tripwireMode, writeTripwireMode, writeClear, readClears } from "../../tripwire/enforce";
import { readMandates, writeMandates, type PublishMandate } from "../../kavach/publish-capability";

const AEGIS_DIR = join(process.env.HOME || "/root", ".aegis");
const readLines = (p: string): string[] => {
  try { return existsSync(p) ? readFileSync(p, "utf-8").split("\n") : []; } catch { return []; }
};

export function registerFirewallRoutes(app: FastifyInstance): void {
  // ── overview: one payload the page renders from ─────────────────────────────
  app.get("/api/firewall/overview", async (req) => {
    const q = (req.query ?? {}) as { since?: string };
    const now = Date.now();
    const since = parseSince(q.since ?? "24h", now) ?? now - 24 * 3600e3;

    const touched = aggregateTouched(
      readLines(join(AEGIS_DIR, "anumati.jsonl")),
      readLines(join(AEGIS_DIR, "tripwire.jsonl")),
      since, now,
    );

    // principals seen by the tripwire, with their current ladder stage
    const clears = readClears();
    const principals = touched.principals.map((p) => {
      const s = stageFor(p.principal);
      return {
        principal: p.principal,
        stage: s.decision.stage,
        hits: s.hits,
        kinds: p.tripwire.kinds,
        cleared: clears[p.principal]?.cleared_at ?? null,
        enforced_refusals: p.anumati.enforced_refusals,
        observations: p.anumati.observations,
        provenance: p.anumati.provenance,
        sample_targets: p.anumati.sample_targets,
      };
    });

    return {
      mode: tripwireMode(),
      totals: touched.totals,
      window: { since: touched.since, until: touched.until },
      principals,
      mandates: readMandates(),
      ceiling: "Computed by this host about itself (PRA-004): survives a lying agent, not a compromised host. Empty = nothing LEDGERED, never 'nothing happened'.",
    };
  });

  // ── actions — each one is the CLI function, projected ───────────────────────
  app.post("/api/firewall/tripwire/clear", async (req, reply) => {
    const b = (req.body ?? {}) as { principal?: string; reason?: string };
    if (!b.principal || !b.reason || b.reason.trim().length < 5) {
      return reply.code(400).send({ error: "principal and a real reason (≥5 chars) are required — a clear is a human judgement, and the reason is its record" });
    }
    const before = stageFor(b.principal).decision.stage;
    writeClear(b.principal, "founder (cockpit)", b.reason.trim());
    return { ok: true, before, after: stageFor(b.principal).decision.stage };
  });

  app.post("/api/firewall/mode", async (req, reply) => {
    const b = (req.body ?? {}) as { mode?: string; confirm?: string };
    if (b.mode !== "observe" && b.mode !== "enforce") return reply.code(400).send({ error: "mode must be observe or enforce" });
    if (b.confirm !== b.mode) {
      return reply.code(400).send({ error: `type the word "${b.mode}" to confirm — flipping containment is a named consent (CA-002), never a button reflex` });
    }
    const current = tripwireMode();
    if (current.mode === b.mode && !current.note) {
      // Already sealed at this mode — say so instead of silently re-writing.
      return { ok: true, unchanged: true, mode: current };
    }
    writeTripwireMode(b.mode);
    return { ok: true, unchanged: false, mode: tripwireMode() };
  });

  app.post("/api/firewall/mandate/grant", async (req, reply) => {
    const b = (req.body ?? {}) as { artifact?: string; reason?: string; ttlHours?: number };
    const ttl = Number(b.ttlHours ?? 24);
    if (!b.artifact || !b.reason || b.reason.trim().length < 5) {
      return reply.code(400).send({ error: "artifact and a real reason are required — the mandate IS the named consent (AFW-012)" });
    }
    if (!Number.isFinite(ttl) || ttl <= 0 || ttl > 336) return reply.code(400).send({ error: "ttlHours must be in (0, 336] — a mandate is a window, never a standing power" });
    const now = Date.now();
    const mandate: PublishMandate = {
      artifact: b.artifact.trim(), reason: b.reason.trim(), granted_by: "founder (cockpit)",
      granted_at: new Date(now).toISOString(), expires_at: new Date(now + ttl * 3600e3).toISOString(),
    };
    writeMandates([...readMandates(now).filter((m) => m.artifact !== mandate.artifact), mandate]);
    return { ok: true, mandates: readMandates() };
  });

  app.post("/api/firewall/mandate/revoke", async (req, reply) => {
    const b = (req.body ?? {}) as { artifact?: string };
    if (!b.artifact) return reply.code(400).send({ error: "artifact required" });
    const live = readMandates();
    const kept = live.filter((m) => m.artifact !== b.artifact);
    if (kept.length === live.length) return reply.code(404).send({ error: `no live mandate named ${b.artifact}` });
    writeMandates(kept);
    return { ok: true, mandates: kept };
  });

  // ── the page ─────────────────────────────────────────────────────────────────
  app.get("/firewall", async (_req, reply) => {
    reply.type("text/html").send(firewallPage());
  });
}

function firewallPage(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Agent Firewall — Cockpit</title>
<style>
  :root { --ink:#0d1117; --paper:#f6f8fa; --card:#ffffff; --accent:#e36209; --ok:#116329; --warn:#9a6700; --bad:#a40e26; --muted:#424a53; --border:#d0d7de; }
  * { box-sizing:border-box; margin:0; padding:0; }
  body { font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif; background:var(--paper); color:var(--ink); line-height:1.5; padding:24px; max-width:1100px; margin:0 auto; }
  h1 { font-size:1.5rem; margin-bottom:4px; }
  .sub { color:var(--muted); font-size:.9rem; margin-bottom:20px; }
  .nav a { color:var(--accent); text-decoration:none; margin-right:16px; font-size:.9rem; }
  .card { background:var(--card); border:1px solid var(--border); border-radius:8px; padding:18px; margin:14px 0; }
  .card h2 { font-size:1.05rem; margin-bottom:10px; }
  .mode { display:flex; align-items:center; gap:14px; flex-wrap:wrap; }
  .pill { display:inline-block; padding:3px 12px; border-radius:999px; font-weight:700; font-size:.85rem; }
  .pill.observe { background:#fff8c5; color:var(--warn); border:1px solid var(--warn); }
  .pill.enforce { background:#dafbe1; color:var(--ok); border:1px solid var(--ok); }
  .pill.watch { background:#ddf4ff; color:#0550ae; }
  .pill.throttle { background:#fff8c5; color:var(--warn); }
  .pill.quarantine, .pill.revoke { background:#ffebe9; color:var(--bad); }
  table { width:100%; border-collapse:collapse; font-size:.88rem; }
  th, td { text-align:left; padding:7px 10px; border-bottom:1px solid var(--border); vertical-align:top; }
  th { color:var(--muted); font-weight:600; font-size:.8rem; text-transform:uppercase; letter-spacing:.04em; }
  button { background:var(--accent); color:#fff; border:0; border-radius:6px; padding:6px 14px; font-weight:600; cursor:pointer; font-size:.85rem; }
  button.quiet { background:#fff; color:var(--ink); border:1px solid var(--border); }
  input, select { padding:6px 10px; border:1px solid var(--border); border-radius:6px; font-size:.88rem; }
  .row { display:flex; gap:10px; flex-wrap:wrap; align-items:center; }
  .ceiling { font-size:.8rem; color:var(--muted); border-left:3px solid var(--border); padding-left:10px; margin-top:16px; }
  .empty { color:var(--muted); font-style:italic; }
  code { background:#eff2f5; padding:1px 5px; border-radius:4px; font-size:.85em; word-break:break-all; }
  .msg { padding:8px 12px; border-radius:6px; margin:8px 0; font-size:.88rem; display:none; }
  .msg.ok { background:#dafbe1; color:var(--ok); display:block; }
  .msg.err { background:#ffebe9; color:var(--bad); display:block; }
</style>
</head>
<body>
<div class="nav"><a href="./">← Dashboard</a><a href="./control-center">Control Center</a></div>
<h1>Agent Firewall — Cockpit</h1>
<div class="sub">The witness face. Every button here runs the same code as the CLI — this page decides nothing on its own.</div>
<div id="msg" class="msg"></div>

<div class="card">
  <h2>Containment mode</h2>
  <div class="mode">
    <span>Currently:</span>
    <span id="modePill" class="pill observe">…</span>
    <span id="modeNote" class="sub" style="margin:0"></span>
  </div>
  <div id="modeAction" style="margin-top:12px"></div>
  <div class="sub" style="margin-top:8px">observe = tripwire stages are reported and ledgered, nothing bites · enforce = throttle/quarantine narrow the agent's valve. You can switch back to observe any time, in one click.</div>
</div>

<div class="card">
  <h2>Watchlist — who tripped what <span class="row" style="float:right"><select id="since" onchange="load()"><option value="24h">last 24h</option><option value="7d">last 7 days</option><option value="30d">last 30 days</option></select></span></h2>
  <table id="watch"><thead><tr><th>Principal</th><th>Stage</th><th>Tripwire</th><th>Refused / Observed</th><th>Outward writes</th><th></th></tr></thead><tbody></tbody></table>
  <div id="watchEmpty" class="empty" style="display:none">Nothing ledgered in this window — quiet is a valid answer.</div>
</div>

<div class="card">
  <h2>Publish mandates — who may push outward</h2>
  <table id="mandates"><thead><tr><th>Artifact</th><th>Reason</th><th>By</th><th>Expires</th><th></th></tr></thead><tbody></tbody></table>
  <div id="mandEmpty" class="empty" style="display:none">No live mandates — every publish would refuse (once enforced) and always leaves a provenance record.</div>
  <div class="row" style="margin-top:10px">
    <input id="gArtifact" placeholder="artifact (name, prefix*, or *)" size="26">
    <input id="gReason" placeholder="reason (recorded forever)" size="30">
    <input id="gTtl" type="number" value="24" min="1" max="336" style="width:80px" title="hours">
    <button onclick="grant()">Grant</button>
  </div>
</div>

<div class="ceiling" id="ceiling"></div>

<script>
// RELATIVE fetches only: this page serves at /firewall direct AND at /dashboard/firewall
// behind nginx. A root-relative '/api/...' escapes the /dashboard/ prefix and lands on the
// static marketing site (GET gets HTML, POST gets 405 — proven by the founder's first click).
const api = (p, opts) => fetch(p.replace(/^\//, ''), Object.assign({headers:{'content-type':'application/json'}}, opts)).then(async r => {
  const j = await r.json().catch(() => null);
  if (!r.ok) throw new Error((j && j.error) || ('HTTP ' + r.status + (r.status === 401 ? ' — session expired, log in again' : '')));
  if (j === null) throw new Error('the server answered with something that is not JSON — wrong path or proxy');
  return j;
});
// errors STAY on screen until the next action — a guard message that flashes is a guard nobody read
const say = (t, ok) => { const m = document.getElementById('msg'); m.textContent = t; m.className = 'msg ' + (ok ? 'ok' : 'err'); if (ok) setTimeout(() => m.className='msg', 8000); };
const esc = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

async function load() {
  try {
    const since = document.getElementById('since').value;
    const d = await api('/api/firewall/overview?since=' + since);
    const pill = document.getElementById('modePill');
    pill.textContent = d.mode.mode.toUpperCase();
    pill.className = 'pill ' + d.mode.mode;
    document.getElementById('modeNote').textContent = d.mode.note || '';
    document.getElementById('ceiling').textContent = d.ceiling;

    // The action offered = the OTHER mode. Arming (→enforce) asks you to type the word;
    // disarming (→observe, the safe direction) is one click, always allowed.
    const act = document.getElementById('modeAction');
    if (d.mode.mode === 'observe') {
      act.innerHTML = 'To make stages BITE, type <b>enforce</b> to confirm: ' +
        '<input id="armWord" placeholder="enforce" size="12"> ' +
        '<button onclick="arm()">Switch to ENFORCE</button>';
    } else {
      act.innerHTML = '<button class="quiet" onclick="disarm()">← Switch back to OBSERVE (safe, one click)</button>';
    }

    const tb = document.querySelector('#watch tbody'); tb.innerHTML = '';
    document.getElementById('watchEmpty').style.display = d.principals.length ? 'none' : 'block';
    for (const p of d.principals) {
      const obs = Object.entries(p.observations).map(([k,v]) => k.replace('ANU-I-','I') + '×' + v).join(', ');
      const prov = p.provenance.map(x => '[' + x.verdict + '] ' + esc(x.detail.slice(0,80))).join('<br>');
      const tr = document.createElement('tr');
      tr.innerHTML = '<td><code>' + esc(p.principal) + '</code>' + (p.cleared ? '<br><span class="sub">cleared ' + esc(p.cleared.slice(0,16)) + '</span>' : '') + '</td>' +
        '<td><span class="pill ' + esc(p.stage) + '">' + esc(p.stage) + '</span><br><span class="sub">' + p.hits + ' hit(s) ' + esc(p.kinds.join('+')) + '</span></td>' +
        '<td>' + (p.kinds.length ? esc(p.kinds.join(', ')) : '—') + '</td>' +
        '<td>' + p.enforced_refusals + ' refused' + (obs ? '<br><span class="sub">' + esc(obs) + '</span>' : '') + '</td>' +
        '<td>' + (prov || '—') + '</td>' +
        '<td>' + (p.stage !== 'watch' || p.hits > 0 ? '<button class="quiet" onclick="clearP(\\'' + esc(p.principal) + '\\')">Clear…</button>' : '') + '</td>';
      tb.appendChild(tr);
    }

    const mb = document.querySelector('#mandates tbody'); mb.innerHTML = '';
    document.getElementById('mandEmpty').style.display = d.mandates.length ? 'none' : 'block';
    for (const m of d.mandates) {
      const tr = document.createElement('tr');
      tr.innerHTML = '<td><code>' + esc(m.artifact) + '</code></td><td>' + esc(m.reason) + '</td><td>' + esc(m.granted_by) + '</td><td>' + esc(m.expires_at.slice(0,16)) + '</td>' +
        '<td><button class="quiet" onclick="revoke(\\'' + esc(m.artifact) + '\\')">Revoke</button></td>';
      mb.appendChild(tr);
    }
  } catch (e) { say('load failed: ' + e.message, false); }
}

async function arm() {
  const v = (document.getElementById('armWord').value || '').trim().toLowerCase();
  if (v !== 'enforce') return say('Type the word enforce exactly to arm the valve (you typed "' + v + '").', false);
  try {
    const r = await api('/api/firewall/mode', {method:'POST', body: JSON.stringify({mode:'enforce', confirm:'enforce'})});
    say(r.unchanged ? 'Already in enforce.' : 'ARMED — containment now bites the agent valve. Switch back to observe any time.', true);
    load();
  } catch (e) { say(e.message, false); }
}
async function disarm() {
  try {
    const r = await api('/api/firewall/mode', {method:'POST', body: JSON.stringify({mode:'observe', confirm:'observe'})});
    say(r.unchanged ? 'Already in observe.' : 'Back to OBSERVE — stages are watched and ledgered, nothing bites.', true);
    load();
  } catch (e) { say(e.message, false); }
}
async function clearP(principal) {
  const reason = prompt('Why is this principal judged safe to de-escalate?\\n(The reason is recorded — this is the human half the ladder requires.)');
  if (!reason) return;
  try { const r = await api('/api/firewall/tripwire/clear', {method:'POST', body: JSON.stringify({principal, reason})}); say(principal + ': ' + r.before + ' → ' + r.after, true); load(); }
  catch (e) { say(e.message, false); }
}
async function grant() {
  const artifact = document.getElementById('gArtifact').value.trim();
  const reason = document.getElementById('gReason').value.trim();
  const ttlHours = Number(document.getElementById('gTtl').value);
  try { await api('/api/firewall/mandate/grant', {method:'POST', body: JSON.stringify({artifact, reason, ttlHours})}); say('mandate granted: ' + artifact, true); load(); }
  catch (e) { say(e.message, false); }
}
async function revoke(artifact) {
  try { await api('/api/firewall/mandate/revoke', {method:'POST', body: JSON.stringify({artifact})}); say('mandate revoked: ' + artifact, true); load(); }
  catch (e) { say(e.message, false); }
}
load();
</script>
</body>
</html>`;
}
