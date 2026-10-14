// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// Flows — the login-only view of real agent flows (GTP-018/024, governed-turn-protocol spec §19, P1c).
//
//   GET /flows            recent flows from the private store (flow-events.db)
//   GET /flows/:id        one flow as a tree: each prompt and each subagent, then its tool calls
//   GET /api/flows        the same list as JSON
//   GET /api/flows/:id    one flow's events and tree as JSON
//
// LOGIN ONLY. None of these is in public-routes.ts, so the dashboard's session guard covers them; that
// is layer B of the founder's ruling (2026-10-15). The public cockpit (/control-center) never shows a
// flow event (layer C, routes/acc.ts). Every value printed comes from hook input and is escaped.

import type { FastifyInstance } from "fastify";
import { buildFlowTree, readFlowEvents, summariseFlows, type FlowBranch } from "../../acc/flow-events";
import type { AccReceipt } from "../../acc/types";

const esc = (s: unknown): string =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string);

const when = (iso: string): string => esc(iso.replace("T", " ").replace(/\.\d+Z$/, "Z"));

function verdictTag(v?: string): string {
  const cls = !v || v === "ALLOWED" ? "ok" : "no";
  return `<span class="v ${cls}">${esc(v ?? "?")}</span>`;
}

function page(title: string, body: string): string {
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} — AEGIS</title>
<style>
  body { font-family: -apple-system, sans-serif; max-width: 1200px; margin: 24px auto; padding: 0 16px; line-height: 1.5; color: #1a1a1a; }
  h1 { color: #0a3d62; border-bottom: 2px solid #ff6b00; padding-bottom: 8px; font-size: 22px; }
  .sub { color: #666; font-size: 13px; margin: 4px 0 20px; }
  .nav { font-size: 13px; margin-bottom: 14px; } .nav a { color: #1a56db; text-decoration: none; margin-right: 14px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; padding: 8px 10px; background: #f4f6f8; border-bottom: 2px solid #ddd; font-size: 11px; color: #555; }
  td { padding: 6px 10px; border-bottom: 1px solid #eee; vertical-align: top; }
  code { font-family: 'SF Mono', monospace; font-size: 12px; }
  .t { color: #888; font-family: 'SF Mono', monospace; font-size: 11px; white-space: nowrap; }
  .v { padding: 1px 8px; border-radius: 10px; font-size: 11px; font-weight: 600; }
  .v.ok { background: #e6f4ea; color: #1e7b34; } .v.no { background: #fde8e8; color: #b42318; }
  .branch { margin: 18px 0 6px; padding: 8px 12px; background: #f4f6f8; border-left: 4px solid #0a3d62; font-size: 13px; }
  .branch.subagent { border-left-color: #ff6b00; }
  .empty { background: #fff8e1; border-left: 4px solid #ff6b00; padding: 14px 18px; border-radius: 4px; }
  .note { color: #888; font-size: 12px; font-style: italic; margin-top: 18px; }
  @media (max-width: 640px) { .hide-sm { display: none; } }
</style></head><body>
<div class="nav"><a href="/flows">Flows</a><a href="/control-center">Control Center</a><a href="/dashboard">Dashboard</a></div>
${body}
</body></html>`;
}

function renderList(): string {
  const flows = summariseFlows(readFlowEvents({ limit: 5000 }), 50);
  if (flows.length === 0) {
    return page("Flows", `<h1>Flows</h1><div class="empty">No flow events yet. The shield records one per tool call (P1b); they appear here as agents work.</div>`);
  }
  const rows = flows.map((f) => `
    <tr>
      <td><a href="/flows/${encodeURIComponent(f.flow_id)}"><code>${esc(f.flow_id)}</code></a></td>
      <td class="t hide-sm">${when(f.first_at)}</td>
      <td class="t">${when(f.last_at)}</td>
      <td>${f.turns}</td>
      <td>${f.blocked ? `<span class="v no">${f.blocked}</span>` : "0"}</td>
      <td>${f.subagents}</td>
    </tr>`).join("");
  return page("Flows", `<h1>Flows</h1>
<p class="sub">Real agent work on this machine, one row per flow (a Claude Code session is one flow). Private: not shown on the public Control Center.</p>
<table><thead><tr><th>Flow</th><th class="hide-sm">First</th><th>Last</th><th>Tool calls</th><th>Blocked</th><th>Subagents</th></tr></thead><tbody>${rows}</tbody></table>
<p class="note">From the newest 5,000 recorded tool calls.</p>`);
}

function renderBranch(b: FlowBranch): string {
  const label = b.kind === "subagent"
    ? `Subagent <code>${esc(b.parent.slice(6))}</code>${b.agent_type ? ` (${esc(b.agent_type)})` : ""}`
    : b.kind === "prompt" ? `Prompt <code>${esc(b.parent.slice(7))}</code>` : esc(b.parent);
  const blocked = b.turns.filter((t) => t.verdict && t.verdict !== "ALLOWED").length;
  const rows = b.turns.map((t: AccReceipt) => `
    <tr>
      <td class="t">${when(t.emitted_at)}</td>
      <td><code>${esc(t.summary ?? "")}</code></td>
      <td>${verdictTag(t.verdict)}</td>
      <td>${(t.rules_fired ?? []).map((r) => `<code>${esc(r)}</code>`).join(" ")}</td>
      <td class="hide-sm"><code>${esc(t.turn_id ?? "")}</code></td>
    </tr>`).join("");
  return `<div class="branch ${b.kind}">${label} · ${b.turns.length} tool call${b.turns.length === 1 ? "" : "s"}${blocked ? ` · <span class="v no">${blocked} blocked</span>` : ""}</div>
<table><thead><tr><th>Time</th><th>Tool</th><th>Decision</th><th>Rule</th><th class="hide-sm">Turn</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function renderFlow(flowId: string): string {
  const events = readFlowEvents({ flowId });
  if (events.length === 0) {
    return page("Flow", `<h1>Flow</h1><div class="empty">No events for <code>${esc(flowId)}</code>.</div>`);
  }
  const tree = buildFlowTree(events);
  return page(`Flow ${flowId}`, `<h1>Flow <code>${esc(flowId)}</code></h1>
<p class="sub">${events.length} tool call${events.length === 1 ? "" : "s"} in ${tree.length} branch${tree.length === 1 ? "" : "es"}, ${when(events[0].emitted_at)} to ${when(events[events.length - 1].emitted_at)}.</p>
${tree.map(renderBranch).join("\n")}
<p class="note">A subagent is shown as its own branch: the hook input does not yet say which prompt started it.</p>`);
}

export function registerFlowRoutes(app: FastifyInstance): void {
  app.get("/flows", async (_req, reply) => {
    reply.header("Content-Type", "text/html; charset=utf-8");
    return renderList();
  });
  app.get<{ Params: { id: string } }>("/flows/:id", async (req, reply) => {
    reply.header("Content-Type", "text/html; charset=utf-8");
    return renderFlow(req.params.id);
  });
  app.get("/api/flows", async () => ({ flows: summariseFlows(readFlowEvents({ limit: 5000 }), 50) }));
  app.get<{ Params: { id: string } }>("/api/flows/:id", async (req) => {
    const events = readFlowEvents({ flowId: req.params.id });
    return { flow_id: req.params.id, events, tree: buildFlowTree(events).map((b) => ({ ...b, turns: b.turns.map((t) => t.turn_id) })) };
  });
}
