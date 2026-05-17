// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// Agentic Control Center — Day 1: /suite inventory page
// @rule:ACC-001 Single-page ACC (this file scopes to /suite for Day 1)
// @rule:ACC-002 Honest empty state — no synthetic data
// @rule:ACC-007 Reuse existing auth (gated by global preHandler in server.ts)
// @rule:ACC-012 Inventory reads consumer's node_modules (process.cwd()), not ACC server's own
// @rule:FR-1, FR-7, FR-14

import type { FastifyInstance } from "fastify";
import { readdirSync, readFileSync, existsSync, statSync } from "fs";
import { join } from "path";

// ── Inventory types ──────────────────────────────────────────────────────────

interface PackageInventoryEntry {
  package_name: string;
  version: string;
  description: string;
  role: string;
  installed: boolean;
}

// Known @rocketlang/* packages and their role labels for the ACC
// Updated as new packages ship per EXTRACTION-QUEUE.md
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

// ── Inventory reader ─────────────────────────────────────────────────────────

/**
 * @rule:ACC-012 — reads from CONSUMER's node_modules, not aegis's own.
 * cwd() is the process current working directory; the consumer launching
 * aegis-dashboard owns this path.
 */
function readSuiteInventory(): PackageInventoryEntry[] {
  const scopeDir = join(process.cwd(), "node_modules", "@rocketlang");

  if (!existsSync(scopeDir)) return [];

  let entries: string[];
  try {
    entries = readdirSync(scopeDir).filter((name) => {
      const p = join(scopeDir, name);
      try {
        return statSync(p).isDirectory();
      } catch {
        return false;
      }
    });
  } catch {
    return [];
  }

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
    } catch {
      // malformed package.json — skip silently rather than crash the inventory
      continue;
    }
  }

  return out;
}

// ── HTML renderer ────────────────────────────────────────────────────────────

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[c]!));
}

/**
 * @rule:ACC-002 — honest empty state when no @rocketlang packages found.
 * Never synthetic. The empty state teaches: ACC is correctly reporting
 * "you have not installed any @rocketlang packages here yet."
 */
function renderEmptyState(): string {
  return `
    <div class="acc-empty">
      <h2>No @rocketlang packages detected in your node_modules</h2>
      <p>This is correct behaviour, not a failure. The ACC reads from <code>${escapeHtml(
        join(process.cwd(), "node_modules", "@rocketlang"),
      )}</code> — that directory does not exist.</p>
      <p>To populate this inventory, install at least one @rocketlang package in this project:</p>
      <pre>npm install @rocketlang/aegis-suite</pre>
      <p>Then reload this page.</p>
    </div>
  `;
}

function renderInventoryTable(entries: PackageInventoryEntry[]): string {
  const rows = entries
    .map(
      (e) => `
      <tr>
        <td><a href="https://www.npmjs.com/package/${escapeHtml(e.package_name)}" target="_blank" rel="noopener">${escapeHtml(e.package_name)}</a></td>
        <td><code>v${escapeHtml(e.version)}</code></td>
        <td>${escapeHtml(e.role)}</td>
        <td>${escapeHtml(e.description)}</td>
      </tr>`,
    )
    .join("");

  return `
    <p class="acc-meta">${entries.length} @rocketlang package${entries.length === 1 ? "" : "s"} installed.</p>
    <table class="acc-suite-table">
      <thead>
        <tr>
          <th>Package</th>
          <th>Version</th>
          <th>Role</th>
          <th>Description</th>
        </tr>
      </thead>
      <tbody>
        ${rows}
      </tbody>
    </table>
    <p class="acc-meta-small">
      ACC reads from <code>${escapeHtml(join(process.cwd(), "node_modules", "@rocketlang"))}</code>.
      To add to this inventory, <code>npm install @rocketlang/&lt;name&gt;</code> from the project root.
    </p>
  `;
}

function renderSuitePage(entries: PackageInventoryEntry[]): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Agentic Control Center — Suite Inventory</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 1100px; margin: 32px auto; padding: 0 24px; color: #1a1a1a; line-height: 1.55; }
    h1 { color: #0a3d62; border-bottom: 2px solid #ff6b00; padding-bottom: 8px; margin-bottom: 4px; }
    h2 { color: #0a3d62; margin-top: 32px; }
    .subtitle { color: #666; font-size: 14px; margin-top: 4px; margin-bottom: 24px; }
    .acc-meta { color: #555; font-size: 14px; margin-bottom: 12px; }
    .acc-meta-small { color: #888; font-size: 12px; margin-top: 16px; font-style: italic; }
    .acc-suite-table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 14px; }
    .acc-suite-table th { text-align: left; padding: 10px 12px; background: #f4f6f8; border-bottom: 2px solid #ddd; font-weight: 600; }
    .acc-suite-table td { padding: 10px 12px; border-bottom: 1px solid #eee; vertical-align: top; }
    .acc-suite-table tr:hover { background: #fafbfc; }
    .acc-suite-table a { color: #ff6b00; text-decoration: none; font-weight: 500; }
    .acc-suite-table a:hover { text-decoration: underline; }
    .acc-suite-table code { background: #f4f6f8; padding: 2px 6px; border-radius: 3px; font-size: 13px; }
    .acc-empty { background: #fff8e1; border-left: 4px solid #ff6b00; padding: 16px 20px; margin-top: 16px; border-radius: 4px; }
    .acc-empty h2 { margin-top: 0; color: #0a3d62; font-size: 18px; }
    .acc-empty pre { background: #1a1a1a; color: #fff; padding: 10px 14px; border-radius: 4px; display: inline-block; font-size: 13px; }
    .acc-empty code { background: #f4f6f8; padding: 2px 6px; border-radius: 3px; font-size: 13px; }
    .nav { margin-bottom: 24px; font-size: 14px; }
    .nav a { color: #1a56db; text-decoration: none; margin-right: 16px; }
    .nav a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="nav">
    <a href="/">← Dashboard</a>
    <a href="/suite">Suite Inventory</a>
  </div>
  <h1>AEGIS Suite Inventory</h1>
  <p class="subtitle">Which @rocketlang/* packages are installed in this project's <code>node_modules</code>.</p>
  ${entries.length === 0 ? renderEmptyState() : renderInventoryTable(entries)}
</body>
</html>`;
}

// ── Route registration ───────────────────────────────────────────────────────

export function registerAccRoutes(app: FastifyInstance): void {
  // @rule:ACC-001 @rule:ACC-007 @rule:FR-1 @rule:FR-14
  // GET /suite — Day 1 inventory page. Auth gated by global preHandler.
  app.get("/suite", async (_req, reply) => {
    const entries = readSuiteInventory();
    reply.header("Content-Type", "text/html; charset=utf-8");
    return renderSuitePage(entries);
  });

  // @rule:ACC-012 @rule:FR-1
  // GET /api/suite/inventory — JSON form for programmatic consumers
  app.get("/api/suite/inventory", async (_req, _reply) => {
    const entries = readSuiteInventory();
    return {
      cwd: process.cwd(),
      scope: "@rocketlang",
      count: entries.length,
      packages: entries,
    };
  });
}
