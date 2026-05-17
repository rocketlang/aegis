// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// Agentic Control Center
// @rule:ACC-001 Single-page cockpit (Day 1 added /suite; Day 3 adds /control-center grid)
// @rule:ACC-002 Honest empty state — no synthetic data
// @rule:ACC-007 Reuse existing auth (gated by global preHandler in server.ts)
// @rule:ACC-008 PRAMANA OSS panel — read-only consume existing src/kernel/merkle-ledger.ts
// @rule:ACC-009 SSE delivery
// @rule:ACC-010 Per-agent timeline at /agent/:id, ordered by emitted_at
// @rule:ACC-012 Inventory reads consumer's node_modules
// @rule:FR-1, FR-6, FR-7, FR-8, FR-10, FR-12, FR-14

import type { FastifyInstance, FastifyReply } from "fastify";
import { readdirSync, readFileSync, existsSync, statSync } from "fs";
import { join } from "path";
import { SqliteEventWriter, defaultAccEventsDbPath } from "../../acc/bus";
import { listCheckpoints } from "../../kernel/merkle-ledger";
import type { AccReceipt } from "../../acc/types";

// ── Inventory (Day 1, unchanged) ─────────────────────────────────────────────

interface PackageInventoryEntry {
  package_name: string;
  version: string;
  description: string;
  role: string;
  installed: boolean;
}

const KNOWN_ROLES: Record<string, string> = {
  "aegis": "agent spend governance + KAVACH DAN gate + spawn-check HanumanG",
  "kavachos": "agent behavior — seccomp-bpf + Falco kernel enforcement",
  "n8n-nodes-kavachos": "n8n community nodes — DAN gate / kernel / budget / audit",
  "aegis-guard": "Five Locks SDK — approval-token + nonce + idempotency + SENSE + quality",
  "chitta-detect": "memory poisoning detection primitives (8 namespaces)",
  "lakshmanrekha": "LLM endpoint probe suite — 8 probes + replayable classifier",
  "hanumang-mandate": "mudrika delegation credential verifier + 7-axis posture scorer",
  "aegis-suite": "meta-package — installs all 6 OSS primitives in one shot",
};

function readSuiteInventory(): PackageInventoryEntry[] {
  const scopeDir = join(process.cwd(), "node_modules", "@rocketlang");
  if (!existsSync(scopeDir)) return [];
  let entries: string[];
  try {
    entries = readdirSync(scopeDir).filter((name) => {
      const p = join(scopeDir, name);
      try { return statSync(p).isDirectory(); } catch { return false; }
    });
  } catch { return []; }
  const out: PackageInventoryEntry[] = [];
  for (const name of entries.sort()) {
    const pkgPath = join(scopeDir, name, "package.json");
    if (!existsSync(pkgPath)) continue;
    try {
      const raw = readFileSync(pkgPath, "utf-8");
      const pkg = JSON.parse(raw) as { version?: string; description?: string };
      out.push({
        package_name: `@rocketlang/${name}`,
        version: pkg.version ?? "?",
        description: pkg.description ?? "",
        role: KNOWN_ROLES[name] ?? "(role not yet catalogued)",
        installed: true,
      });
    } catch { continue; }
  }
  return out;
}

// ── HTML helpers ─────────────────────────────────────────────────────────────

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]!));
}

function verdictBadge(verdict?: string): string {
  if (!verdict) return '<span class="badge badge-neutral">—</span>';
  const v = verdict.toUpperCase();
  let cls = 'badge-neutral';
  if (v === 'PASS' || v.startsWith('A-') || v.startsWith('B-')) cls = 'badge-pass';
  else if (v === 'WARN' || v === 'ADVISORY' || v === 'PARTIAL' || v.startsWith('C-')) cls = 'badge-warn';
  else if (v === 'FAIL' || v === 'BLOCK' || v === 'INJECT_SUSPECT' || v === 'COMPLIED' || v === 'EXPIRED' || v === 'REVOKED' || v === 'ERRORED' || v.startsWith('D-') || v.startsWith('F-')) cls = 'badge-fail';
  return `<span class="badge ${cls}">${escapeHtml(verdict)}</span>`;
}

// ── Zone rendering ───────────────────────────────────────────────────────────

interface ZoneSpec {
  primitive: string;
  label: string;
  role: string;
  setup_hint: string;
}

const ZONES: ZoneSpec[] = [
  { primitive: 'aegis-guard',      label: 'Five Locks',         role: 'approval / nonce / idempotency / SENSE',                    setup_hint: 'wireAllToBus() activates lock.* events' },
  { primitive: 'chitta-detect',    label: 'Memory Poisoning',   role: 'RAG trust / imperatives / fingerprints / scan',             setup_hint: 'wireAllToBus() activates scan.evaluated events' },
  { primitive: 'lakshmanrekha',    label: 'LLM Probes',         role: '8 probes / refusal classifier / multi-provider runner',     setup_hint: 'wireAllToBus() + runProbe() activates probe.run events' },
  { primitive: 'hanumang-mandate', label: 'Mandate & Posture',  role: 'mudrika verifier + 7-axis posture scorer',                  setup_hint: 'wireAllToBus() activates mudrika.* + posture.* events' },
  { primitive: 'aegis',            label: 'AEGIS Core',         role: 'spend governance + KAVACH DAN gate + spawn-check HanumanG', setup_hint: 'aegis-monitor + aegis init wire the existing dashboard events' },
  { primitive: 'kavachos',         label: 'KavachOS',           role: 'seccomp-bpf + Falco kernel enforcement',                    setup_hint: 'kavachos run wires kernel-level events' },
];

function renderZone(spec: ZoneSpec, writer: SqliteEventWriter | null): string {
  let events: AccReceipt[] = [];
  if (writer) {
    try { events = writer.queryByPrimitive(spec.primitive, 20); } catch { events = []; }
  }

  let body: string;
  if (events.length === 0) {
    // @rule:ACC-002 @rule:ACC-YK-001 — honest empty state
    body = `
      <div class="zone-empty">
        <p class="empty-line">No events recorded yet for <code>${escapeHtml(spec.primitive)}</code>.</p>
        <p class="empty-hint">${escapeHtml(spec.setup_hint)} — then events appear here. <a href="https://www.npmjs.com/package/@rocketlang/${escapeHtml(spec.primitive)}" target="_blank" rel="noopener">npm docs</a></p>
      </div>`;
  } else {
    const rows = events.map((e) => `
      <tr>
        <td class="t-when"><time datetime="${escapeHtml(e.emitted_at)}">${escapeHtml(e.emitted_at.split('T')[1]?.split('.')[0] ?? e.emitted_at)}</time></td>
        <td class="t-event"><code>${escapeHtml(e.event_type)}</code></td>
        <td class="t-verdict">${verdictBadge(e.verdict)}</td>
        <td class="t-agent">${e.agent_id ? `<a href="/agent/${encodeURIComponent(e.agent_id)}"><code>${escapeHtml(e.agent_id)}</code></a>` : '—'}</td>
        <td class="t-summary">${escapeHtml(e.summary ?? '')}</td>
      </tr>`).join('');
    body = `
      <table class="zone-table">
        <thead><tr><th>Time</th><th>Event</th><th>Verdict</th><th>Agent</th><th>Summary</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>`;
  }

  return `
    <section class="zone" data-primitive="${escapeHtml(spec.primitive)}">
      <header class="zone-header">
        <h3>${escapeHtml(spec.label)}</h3>
        <span class="zone-role">${escapeHtml(spec.role)}</span>
        <span class="zone-count">${events.length}</span>
      </header>
      <div class="zone-body">${body}</div>
    </section>`;
}

// ── PRAMANA OSS panel — read-only consume existing Merkle ledger ─────────────

function renderPramanaPanel(): string {
  // @rule:ACC-008 — read-only consume already-shipping merkle-ledger.ts (no new infra)
  let checkpoints: ReturnType<typeof listCheckpoints> = [];
  try { checkpoints = listCheckpoints(10); } catch { checkpoints = []; }

  if (checkpoints.length === 0) {
    // @rule:NFR-6 — graceful degradation when no checkpoints yet
    return `
      <section class="zone pramana-zone" data-primitive="pramana">
        <header class="zone-header">
          <h3>PRAMANA — Tamper-Evident Audit Chain</h3>
          <span class="zone-role">CT-style Merkle tree + Ed25519 STH + S3 anchoring (already AGPL-3.0 in aegis v2.1.0)</span>
          <span class="zone-count">0</span>
        </header>
        <div class="zone-body">
          <div class="zone-empty">
            <p class="empty-line">No PRAMANA checkpoints recorded yet.</p>
            <p class="empty-hint">PRAMANA Merkle checkpoints are created when the receipt-batching ledger flushes. See <code>src/kernel/merkle-ledger.ts</code> + <code>src/kernel/merkle-anchor.ts</code> in <code>@rocketlang/aegis</code>.</p>
          </div>
        </div>
      </section>`;
  }

  const rows = checkpoints.map((c) => `
    <tr>
      <td><time datetime="${escapeHtml(c.created_at)}">${escapeHtml(c.created_at.split('T')[1]?.split('.')[0] ?? c.created_at)}</time></td>
      <td><code class="checkpoint-id">${escapeHtml(c.checkpoint_id)}</code></td>
      <td>${c.tree_size}</td>
      <td><code class="merkle-root">${escapeHtml(c.sha256_root_hash.slice(0, 16))}…</code></td>
    </tr>`).join('');
  return `
    <section class="zone pramana-zone" data-primitive="pramana">
      <header class="zone-header">
        <h3>PRAMANA — Tamper-Evident Audit Chain</h3>
        <span class="zone-role">CT-style Merkle tree + Ed25519 STH + S3 anchoring (AGPL-3.0)</span>
        <span class="zone-count">${checkpoints.length}</span>
      </header>
      <div class="zone-body">
        <table class="zone-table">
          <thead><tr><th>Created</th><th>Checkpoint</th><th>Tree size</th><th>Merkle root (prefix)</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </section>`;
}

// ── Page render ──────────────────────────────────────────────────────────────

const STYLES = `
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 1400px; margin: 24px auto; padding: 0 24px; color: #1a1a1a; line-height: 1.5; }
  h1 { color: #0a3d62; border-bottom: 2px solid #ff6b00; padding-bottom: 8px; margin-bottom: 4px; font-size: 22px; }
  .subtitle { color: #666; font-size: 13px; margin-top: 4px; margin-bottom: 16px; }
  .nav { margin-bottom: 16px; font-size: 13px; }
  .nav a { color: #1a56db; text-decoration: none; margin-right: 14px; }
  .nav a:hover { text-decoration: underline; }
  .nav .live-indicator { display: inline-block; margin-left: 12px; padding: 2px 8px; background: #f0f0f0; border-radius: 10px; color: #666; font-size: 12px; }
  .nav .live-indicator.on { background: #d4edda; color: #155724; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(440px, 1fr)); gap: 14px; }
  .zone { border: 1px solid #e0e0e0; border-radius: 6px; background: #fff; overflow: hidden; }
  .zone-header { display: flex; align-items: center; gap: 12px; padding: 10px 14px; background: #f4f6f8; border-bottom: 1px solid #e0e0e0; }
  .zone-header h3 { margin: 0; color: #0a3d62; font-size: 15px; font-weight: 600; flex: 0 0 auto; }
  .zone-role { color: #666; font-size: 11px; flex: 1; }
  .zone-count { background: #fff; padding: 2px 8px; border-radius: 10px; font-size: 11px; color: #666; border: 1px solid #ddd; font-weight: 500; }
  .zone-body { padding: 0; min-height: 60px; }
  .zone-empty { padding: 16px 14px; }
  .empty-line { margin: 0 0 6px 0; color: #555; font-size: 13px; }
  .empty-hint { margin: 0; color: #888; font-size: 11px; font-style: italic; }
  .zone-table { width: 100%; border-collapse: collapse; font-size: 12px; }
  .zone-table th { text-align: left; padding: 6px 10px; background: #fafbfc; border-bottom: 1px solid #eee; font-weight: 600; color: #555; font-size: 11px; }
  .zone-table td { padding: 5px 10px; border-bottom: 1px solid #f4f4f4; vertical-align: top; }
  .zone-table tr:last-child td { border-bottom: none; }
  .zone-table tr:hover { background: #fafbfc; }
  .t-when { color: #888; font-family: 'SF Mono', monospace; font-size: 11px; white-space: nowrap; }
  .t-event code { font-family: 'SF Mono', monospace; font-size: 11px; }
  .t-agent code { font-family: 'SF Mono', monospace; font-size: 11px; }
  .t-agent a { color: #1a56db; text-decoration: none; }
  .t-summary { color: #555; font-size: 12px; max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .badge { display: inline-block; padding: 1px 8px; border-radius: 10px; font-size: 10px; font-weight: 600; text-transform: uppercase; }
  .badge-pass { background: #d4edda; color: #155724; }
  .badge-warn { background: #fff3cd; color: #856404; }
  .badge-fail { background: #f8d7da; color: #721c24; }
  .badge-neutral { background: #e9ecef; color: #6c757d; }
  .pramana-zone { grid-column: 1 / -1; }
  .checkpoint-id { font-size: 11px; }
  .merkle-root { font-size: 11px; color: #666; }
`;

function renderControlCenterPage(writer: SqliteEventWriter | null, headerNote: string): string {
  const zones = ZONES.map((z) => renderZone(z, writer)).join('\n');
  const pramana = renderPramanaPanel();
  const totalCount = writer ? (() => { try { return writer.totalCount(); } catch { return 0; } })() : 0;
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Agentic Control Center — AEGIS</title>
  <style>${STYLES}</style>
</head>
<body>
  <div class="nav">
    <a href="/">← Dashboard</a>
    <a href="/control-center">Control Center</a>
    <a href="/suite">Suite Inventory</a>
    <span class="live-indicator" id="live-indicator">○ idle</span>
  </div>
  <h1>Agentic Control Center</h1>
  <p class="subtitle">${escapeHtml(headerNote)} · total receipts: <strong>${totalCount}</strong></p>
  <div class="grid">
    ${zones}
    ${pramana}
  </div>
  <script>
    // @rule:ACC-009 — SSE for live updates
    (function() {
      const ind = document.getElementById('live-indicator');
      let es;
      try {
        es = new EventSource('/api/acc/events/stream');
        es.onopen = () => { ind.textContent = '● live'; ind.classList.add('on'); };
        es.onerror = () => { ind.textContent = '○ disconnected'; ind.classList.remove('on'); };
        es.addEventListener('receipt', () => {
          // event arrived — reload after small debounce to refresh zones
          clearTimeout(window._reloadTimer);
          window._reloadTimer = setTimeout(() => location.reload(), 800);
        });
      } catch (err) {
        console.error('SSE setup failed', err);
      }
    })();
  </script>
</body>
</html>`;
}

// ── Suite inventory page (Day 1 — unchanged) ─────────────────────────────────

function renderEmptyInventory(): string {
  return `
    <div class="acc-empty">
      <h2>No @rocketlang packages detected in your node_modules</h2>
      <p>This is correct behaviour, not a failure. The ACC reads from <code>${escapeHtml(
        join(process.cwd(), "node_modules", "@rocketlang"),
      )}</code> — that directory does not exist.</p>
      <p>To populate this inventory, install at least one @rocketlang package in this project:</p>
      <pre>npm install @rocketlang/aegis-suite</pre>
      <p>Then reload this page.</p>
    </div>`;
}

function renderInventoryTable(entries: PackageInventoryEntry[]): string {
  const rows = entries.map((e) => `
      <tr>
        <td><a href="https://www.npmjs.com/package/${escapeHtml(e.package_name)}" target="_blank" rel="noopener">${escapeHtml(e.package_name)}</a></td>
        <td><code>v${escapeHtml(e.version)}</code></td>
        <td>${escapeHtml(e.role)}</td>
        <td>${escapeHtml(e.description)}</td>
      </tr>`).join("");
  return `
    <p class="acc-meta">${entries.length} @rocketlang package${entries.length === 1 ? "" : "s"} installed.</p>
    <table class="acc-suite-table">
      <thead><tr><th>Package</th><th>Version</th><th>Role</th><th>Description</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
    <p class="acc-meta-small">ACC reads from <code>${escapeHtml(join(process.cwd(), "node_modules", "@rocketlang"))}</code>.</p>`;
}

function renderSuitePage(entries: PackageInventoryEntry[]): string {
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Agentic Control Center — Suite Inventory</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 1100px; margin: 32px auto; padding: 0 24px; color: #1a1a1a; line-height: 1.55; }
  h1 { color: #0a3d62; border-bottom: 2px solid #ff6b00; padding-bottom: 8px; margin-bottom: 4px; }
  .subtitle { color: #666; font-size: 14px; margin-top: 4px; margin-bottom: 24px; }
  .acc-meta { color: #555; font-size: 14px; margin-bottom: 12px; }
  .acc-meta-small { color: #888; font-size: 12px; margin-top: 16px; font-style: italic; }
  .acc-suite-table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 14px; }
  .acc-suite-table th { text-align: left; padding: 10px 12px; background: #f4f6f8; border-bottom: 2px solid #ddd; font-weight: 600; }
  .acc-suite-table td { padding: 10px 12px; border-bottom: 1px solid #eee; vertical-align: top; }
  .acc-suite-table tr:hover { background: #fafbfc; }
  .acc-suite-table a { color: #ff6b00; text-decoration: none; font-weight: 500; }
  .acc-suite-table code { background: #f4f6f8; padding: 2px 6px; border-radius: 3px; font-size: 13px; }
  .acc-empty { background: #fff8e1; border-left: 4px solid #ff6b00; padding: 16px 20px; margin-top: 16px; border-radius: 4px; }
  .acc-empty h2 { margin-top: 0; color: #0a3d62; font-size: 18px; }
  .acc-empty pre { background: #1a1a1a; color: #fff; padding: 10px 14px; border-radius: 4px; display: inline-block; font-size: 13px; }
  .nav { margin-bottom: 24px; font-size: 14px; }
  .nav a { color: #1a56db; text-decoration: none; margin-right: 16px; }
</style></head>
<body>
  <div class="nav"><a href="/">← Dashboard</a><a href="/control-center">Control Center</a><a href="/suite">Suite Inventory</a></div>
  <h1>AEGIS Suite Inventory</h1>
  <p class="subtitle">Which @rocketlang/* packages are installed in this project's <code>node_modules</code>.</p>
  ${entries.length === 0 ? renderEmptyInventory() : renderInventoryTable(entries)}
</body></html>`;
}

// ── Agent timeline page ──────────────────────────────────────────────────────

function renderAgentTimeline(agentId: string, events: AccReceipt[]): string {
  let body: string;
  if (events.length === 0) {
    body = `
      <div class="acc-empty">
        <p>No events recorded for agent <code>${escapeHtml(agentId)}</code>.</p>
        <p class="acc-meta-small">Verify the agent ID and check that <code>wireAllToBus()</code> is called in the consumer process. Events with this agent_id will appear here once recorded.</p>
      </div>`;
  } else {
    const rows = events.map((e) => `
      <tr>
        <td class="t-when"><time datetime="${escapeHtml(e.emitted_at)}">${escapeHtml(e.emitted_at)}</time></td>
        <td><span class="primitive-tag">${escapeHtml(e.primitive)}</span></td>
        <td><code>${escapeHtml(e.event_type)}</code></td>
        <td>${verdictBadge(e.verdict)}</td>
        <td>${escapeHtml(e.summary ?? '')}</td>
        <td class="t-rules">${(e.rules_fired ?? []).map((r) => `<code class="rule">${escapeHtml(r)}</code>`).join(' ')}</td>
      </tr>`).join('');
    body = `
      <p class="acc-meta">${events.length} event${events.length === 1 ? '' : 's'} for this agent, ordered by emission time.</p>
      <table class="acc-suite-table timeline">
        <thead><tr><th>Time</th><th>Primitive</th><th>Event</th><th>Verdict</th><th>Summary</th><th>Rules</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>`;
  }
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Agent ${escapeHtml(agentId)} — Agentic Control Center</title>
<style>
  body { font-family: -apple-system, sans-serif; max-width: 1400px; margin: 24px auto; padding: 0 24px; line-height: 1.5; color: #1a1a1a; }
  h1 { color: #0a3d62; border-bottom: 2px solid #ff6b00; padding-bottom: 8px; font-size: 22px; }
  .subtitle { color: #666; font-size: 13px; margin: 4px 0 24px 0; }
  .nav { margin-bottom: 16px; font-size: 13px; }
  .nav a { color: #1a56db; text-decoration: none; margin-right: 14px; }
  .acc-meta { color: #555; font-size: 14px; }
  .acc-meta-small { color: #888; font-size: 12px; font-style: italic; margin-top: 8px; }
  .acc-empty { background: #fff8e1; border-left: 4px solid #ff6b00; padding: 16px 20px; border-radius: 4px; margin-top: 16px; }
  .acc-suite-table { width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 8px; }
  .acc-suite-table th { text-align: left; padding: 8px 10px; background: #f4f6f8; border-bottom: 2px solid #ddd; font-weight: 600; font-size: 11px; color: #555; }
  .acc-suite-table td { padding: 6px 10px; border-bottom: 1px solid #eee; vertical-align: top; }
  .t-when { color: #888; font-family: 'SF Mono', monospace; font-size: 11px; white-space: nowrap; }
  .primitive-tag { background: #f0f4f8; padding: 2px 8px; border-radius: 10px; font-size: 11px; color: #0a3d62; font-weight: 500; }
  .badge { display: inline-block; padding: 1px 8px; border-radius: 10px; font-size: 10px; font-weight: 600; text-transform: uppercase; }
  .badge-pass { background: #d4edda; color: #155724; }
  .badge-warn { background: #fff3cd; color: #856404; }
  .badge-fail { background: #f8d7da; color: #721c24; }
  .badge-neutral { background: #e9ecef; color: #6c757d; }
  .rule { font-size: 10px; background: #f4f6f8; padding: 1px 5px; border-radius: 3px; color: #666; }
  .t-rules { max-width: 200px; }
  code { background: #f4f6f8; padding: 1px 4px; border-radius: 3px; font-size: 12px; }
</style></head>
<body>
  <div class="nav"><a href="/">← Dashboard</a><a href="/control-center">Control Center</a><a href="/suite">Suite Inventory</a></div>
  <h1>Agent Timeline — <code>${escapeHtml(agentId)}</code></h1>
  <p class="subtitle">All events recorded for this agent across all primitives, ordered by emission time.</p>
  ${body}
</body></html>`;
}

// ── SSE polling ──────────────────────────────────────────────────────────────
// @rule:ACC-009 — SSE delivery
// @rule:ACC-011 — process-local default — poll SQLite for changes

interface SseClient { lastId: number; reply: FastifyReply; }

function setupSse(_app: FastifyInstance, writer: SqliteEventWriter | null, reply: FastifyReply): void {
  reply.raw.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  reply.raw.write(': connected to acc events stream\n\n');

  if (!writer) {
    reply.raw.write('event: closed\ndata: {"reason":"no writer"}\n\n');
    reply.raw.end();
    return;
  }

  let lastId = writer.maxId();
  const tick = (): void => {
    try {
      const fresh = writer.queryNewer(lastId, 50);
      for (const r of fresh) {
        lastId = (r as { id: number }).id;
        const data = JSON.stringify({
          receipt_id: r.receipt_id, primitive: r.primitive, event_type: r.event_type,
          emitted_at: r.emitted_at, agent_id: r.agent_id ?? null, verdict: r.verdict ?? null,
        });
        reply.raw.write(`event: receipt\ndata: ${data}\n\n`);
      }
    } catch {
      // poll failure non-fatal; next tick may succeed
    }
  };
  const interval = setInterval(tick, 1500);
  const heartbeat = setInterval(() => reply.raw.write(': heartbeat\n\n'), 30_000);
  reply.raw.on('close', () => { clearInterval(interval); clearInterval(heartbeat); });
}

// ── Writer lazy init (single instance per dashboard process) ─────────────────

let _writer: SqliteEventWriter | null = null;
function getWriter(): SqliteEventWriter | null {
  if (_writer) return _writer;
  try {
    _writer = new SqliteEventWriter();
    return _writer;
  } catch {
    return null;
  }
}

// ── Route registration ───────────────────────────────────────────────────────

export function registerAccRoutes(app: FastifyInstance): void {
  // GET /suite — Day 1 inventory page
  app.get("/suite", async (_req, reply) => {
    const entries = readSuiteInventory();
    reply.header("Content-Type", "text/html; charset=utf-8");
    return renderSuitePage(entries);
  });

  // GET /api/suite/inventory — Day 1 JSON inventory
  app.get("/api/suite/inventory", async () => {
    const entries = readSuiteInventory();
    return { cwd: process.cwd(), scope: "@rocketlang", count: entries.length, packages: entries };
  });

  // @rule:ACC-001 @rule:FR-6 — Day 3 main cockpit grid
  app.get("/control-center", async (_req, reply) => {
    const writer = getWriter();
    const path = writer ? defaultAccEventsDbPath() : '(SQLite not initialised)';
    reply.header("Content-Type", "text/html; charset=utf-8");
    return renderControlCenterPage(writer, `events from ${escapeHtml(path)}`);
  });

  // @rule:ACC-010 @rule:FR-12 — per-agent timeline
  app.get<{ Params: { id: string } }>("/agent/:id", async (req, reply) => {
    const agentId = req.params.id;
    const writer = getWriter();
    let events: AccReceipt[] = [];
    if (writer) {
      try { events = writer.queryByAgent(agentId, 500); } catch { events = []; }
    }
    reply.header("Content-Type", "text/html; charset=utf-8");
    return renderAgentTimeline(agentId, events);
  });

  // @rule:ACC-009 @rule:FR-8 — SSE stream of new receipts
  app.get("/api/acc/events/stream", async (_req, reply) => {
    const writer = getWriter();
    setupSse(app, writer, reply);
    return reply;
  });

  // GET /api/acc/health — JSON of total event count + per-primitive counts
  app.get("/api/acc/health", async () => {
    const writer = getWriter();
    if (!writer) return { sqlite: false, total: 0, by_primitive: {} };
    let by_primitive: Record<string, number> = {};
    let total = 0;
    try { by_primitive = writer.countsByPrimitive(); total = writer.totalCount(); } catch {}
    return { sqlite: true, db_path: defaultAccEventsDbPath(), total, by_primitive };
  });

  // GET /api/acc/events?primitive=&limit= — JSON event query
  app.get<{ Querystring: { primitive?: string; agent_id?: string; limit?: string } }>(
    "/api/acc/events",
    async (req) => {
      const writer = getWriter();
      if (!writer) return { events: [], note: "no writer" };
      const limit = Math.min(parseInt(req.query.limit ?? "50", 10) || 50, 500);
      try {
        if (req.query.primitive) {
          return { events: writer.queryByPrimitive(req.query.primitive, limit) };
        }
        if (req.query.agent_id) {
          return { events: writer.queryByAgent(req.query.agent_id, limit) };
        }
        return { events: writer.queryNewer(0, limit) };
      } catch {
        return { events: [], error: "query failed" };
      }
    },
  );
}
