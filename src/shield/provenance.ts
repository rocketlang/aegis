// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// AEGIS — tool-result provenance ring (AF-T-710).
//
// "A plugin injected the agent" is a claim about what the agent READ before it ACTED. An egress
// record that carries only the command cannot support or refute it. So every tool RESULT is
// noted here (PostToolUse), per session, as a bounded ring: which source class produced it
// (mcp:<server>, web, plugin-skill:<ns>, agent, file, local), its size, a hash, and whether an
// injection pattern matched. When an egress rule fires, the refusal/receipt carries the chain
// that preceded it — attribution becomes checkable instead of asserted.
//
// Stores NO content: hash12 + byte count + rule id only (the ring must not become a copy of
// what the agent read). RECORDS ONLY — nothing here blocks; escalation on "external source then
// egress" is a separate, founder-ruled step.
//
// CEILING: the ring sees tool results, not the system prompt, CLAUDE.md, or skill text loaded
// outside a tool call; and a matched injection pattern is a LIST hit, not proof of intent.
// @rule:FP-018 @rule:AFW-012

import { existsSync, readFileSync, writeFileSync, mkdirSync, renameSync } from "fs";
import { join } from "path";
import { createHash } from "crypto";
import { getAegisDir } from "../core/config";
import { detectInjection, loadShieldRules } from "./injection-detector";

export type SourceClass = "mcp" | "web" | "plugin-skill" | "agent" | "file" | "local" | "other";

export interface ProvenanceEntry {
  ts: string;
  tool: string;
  /** e.g. "mcp:ankr-mcp", "web", "plugin-skill:sales", "file", "local" */
  source: string;
  cls: SourceClass;
  /** content from outside this box/tree entered the context through this result */
  external: boolean;
  bytes: number;
  hash12: string;
  /** injection rule id matched in the result text, or null */
  injection: string | null;
}

const RING_MAX = 20;
const SCAN_MAX_BYTES = 64 * 1024;

export function classifySource(toolName: string, input: Record<string, unknown> = {}): { source: string; cls: SourceClass; external: boolean } {
  // mcp__<server>__<tool> — the server segment is everything between the first two "__"
  if (toolName.startsWith("mcp__")) {
    const server = toolName.split("__")[1] || "?";
    return { source: `mcp:${server}`, cls: "mcp", external: true };
  }
  if (toolName === "WebFetch" || toolName === "WebSearch") return { source: "web", cls: "web", external: true };
  if (toolName === "Skill") {
    const name = typeof input.skill === "string" ? input.skill : "";
    // a namespaced skill ("plugin:skill") is third-party plugin text entering the context
    if (name.includes(":")) return { source: `plugin-skill:${name.split(":")[0]}`, cls: "plugin-skill", external: true };
    return { source: `skill:${name || "?"}`, cls: "local", external: false };
  }
  if (toolName === "Agent") return { source: "agent", cls: "agent", external: false };
  if (toolName === "Read" || toolName === "Grep" || toolName === "Glob") return { source: "file", cls: "file", external: false };
  if (["Bash", "Edit", "Write", "NotebookEdit"].includes(toolName)) return { source: "local", cls: "local", external: false };
  return { source: toolName || "other", cls: "other", external: false };
}

function responseText(resp: unknown): string {
  if (typeof resp === "string") return resp;
  try { return JSON.stringify(resp ?? ""); } catch { return ""; }
}

/** Pure: the entry a tool result produces. No IO beyond loading shield rules. */
export function provenanceEntry(toolName: string, input: Record<string, unknown> | undefined, resp: unknown, nowIso = new Date().toISOString()): ProvenanceEntry {
  const text = responseText(resp);
  const { source, cls, external } = classifySource(toolName, input ?? {});
  let injection: string | null = null;
  try {
    const r = detectInjection(text.slice(0, SCAN_MAX_BYTES), loadShieldRules());
    if (r.verdict !== "PASS") injection = r.rule_id;
  } catch { /* a scan failure records null, never blocks */ }
  return {
    ts: nowIso, tool: toolName, source, cls, external,
    bytes: Buffer.byteLength(text),
    hash12: createHash("sha256").update(text).digest("hex").slice(0, 12),
    injection,
  };
}

function ringPath(sessionId: string): string {
  const dir = join(getAegisDir(), "provenance");
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });
  return join(dir, `${sessionId.replace(/[^A-Za-z0-9_-]/g, "_")}.json`);
}

export function readRing(sessionId: string): ProvenanceEntry[] {
  try {
    const p = ringPath(sessionId);
    return existsSync(p) ? (JSON.parse(readFileSync(p, "utf-8")) as ProvenanceEntry[]) : [];
  } catch { return []; }
}

/** PostToolUse: append this result to the session ring (atomic tmp+rename, bounded). */
export function recordProvenance(sessionId: string, toolName: string, input: Record<string, unknown> | undefined, resp: unknown): void {
  try {
    const ring = readRing(sessionId);
    ring.push(provenanceEntry(toolName, input, resp));
    const p = ringPath(sessionId);
    writeFileSync(p + ".tmp", JSON.stringify(ring.slice(-RING_MAX)), { mode: 0o600 });
    renameSync(p + ".tmp", p);
  } catch { /* never block tool execution */ }
}

export interface PrecededBy {
  /** the last n results, newest first */
  chain: Array<Pick<ProvenanceEntry, "source" | "external" | "bytes" | "hash12" | "injection">>;
  external_sources: string[];
  injection_hits: string[];
  /** one line for a refusal/receipt */
  summary: string;
}

/** Pure over a ring: what preceded the action. */
export function precededBy(ring: ProvenanceEntry[], n = 5): PrecededBy {
  const recent = ring.slice(-n).reverse();
  const chain = recent.map(({ source, external, bytes, hash12, injection }) => ({ source, external, bytes, hash12, injection }));
  const external_sources = [...new Set(recent.filter((e) => e.external).map((e) => e.source))];
  const injection_hits = recent.filter((e) => e.injection).map((e) => `${e.source}:${e.injection}`);
  const summary = recent.length === 0
    ? "preceded by: no recorded tool results"
    : `preceded by (newest first): ${recent.map((e) => e.source + (e.injection ? `[${e.injection}]` : "")).join(" ← ")}` +
      (external_sources.length ? ` · external: ${external_sources.join(", ")}` : " · external: none");
  return { chain, external_sources, injection_hits, summary };
}

export function precededByForSession(sessionId: string, n = 5): PrecededBy {
  return precededBy(readRing(sessionId), n);
}
