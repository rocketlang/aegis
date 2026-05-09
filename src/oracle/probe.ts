// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// oracle/probe.ts — Session-Oracle Phase 2 (SOR-T-201 to SOR-T-205)
// Active file probe + composite service detection.
//
// @rule:SOR-008 k_mask is claimed truth — probe validates against ground truth
// @rule:SOR-YK-003 HIGH severity = overclaim = veto gate in BitmaskOS
// @rule:SOR-YK-004 MEDIUM severity = drift — surface, do not veto
// @rule:SOR-INF-003 probe veto prevents dream-phase from endorsing overclaims

import { readFileSync, existsSync, readdirSync } from "fs";
import { join } from "path";
import { execSync } from "child_process";

const SERVICES_JSON = "/root/.ankr/config/services.json";
const PROPOSALS_DIR = "/root/proposals";
const TODOS_DIR     = "/root/ankr-todos";

// k_mask bit → doctype — must stay in sync with DOC_TYPES in session-start.ts
const BIT_TO_DOCTYPE = ["brainstorm", "project", "logics", "todo", "deep-knowledge"] as const;
type DocType = typeof BIT_TO_DOCTYPE[number];

export type ProbeSeverity = "HIGH" | "MEDIUM" | "LOW";

export interface ProbeItem {
  service_key: string;
  bit:         number | null;  // null for non-bit-specific findings
  claim:       string;
  actual:      string;
  severity:    ProbeSeverity;
  detail:      string;
}

export interface ProbeResult {
  session_id:   string;
  service_key:  string;
  probed_at:    string;
  items:        ProbeItem[];
  high_count:   number;
  medium_count: number;
}

// ─── SOR-T-205: Composite service detection ────────────────────────────────────

function safeExec(cmd: string): string | null {
  try {
    return execSync(cmd, { encoding: "utf-8", timeout: 1500, stdio: ["pipe","pipe","pipe"] }).trim() || null;
  } catch { return null; }
}

export function detectServiceComposite(
  cwd: string,
  gitRemote: string | null
): { service_key: string | null; detection_method: string } {
  let registry: Record<string, unknown> = {};
  try {
    registry = JSON.parse(readFileSync(SERVICES_JSON, "utf-8")).services ?? {};
  } catch { return { service_key: null, detection_method: "none" }; }

  // 1. CWD last component — fastest, most reliable
  const cwdKey = cwd.split("/").pop() ?? "";
  if (cwdKey && registry[cwdKey]) return { service_key: cwdKey, detection_method: "cwd" };

  // 2. CWD strip -backend / -api suffix
  const stripped = cwdKey.replace(/-(backend|api)$/, "");
  if (stripped !== cwdKey && registry[stripped]) return { service_key: stripped, detection_method: "cwd-stripped" };

  // 3. Monorepo: ankr-labs-nx/apps/{key} pattern
  const monoMatch = cwd.match(/ankr-labs-nx\/apps\/([^/]+)/);
  if (monoMatch && registry[monoMatch[1]]) return { service_key: monoMatch[1], detection_method: "monorepo-apps" };

  // 4. CLAUDE.md service_key: field — explicit override
  const claudeMd = join(cwd, "CLAUDE.md");
  if (existsSync(claudeMd)) {
    try {
      const m = readFileSync(claudeMd, "utf-8").match(/^service_key:\s*(\S+)/m);
      if (m && registry[m[1]]) return { service_key: m[1], detection_method: "claude-md" };
    } catch {}
  }

  // 5. git remote → repo name → registry lookup
  const remote = gitRemote ?? safeExec("git remote get-url origin");
  if (remote) {
    const repoName = remote.replace(/\.git$/, "").split(/[/:]/).pop() ?? "";
    if (repoName && registry[repoName]) return { service_key: repoName, detection_method: "git-remote" };
    const unprefixed = repoName.replace(/^ankr-?/, "");
    if (unprefixed && unprefixed !== repoName && registry[unprefixed]) {
      return { service_key: unprefixed, detection_method: "git-remote-stripped" };
    }
  }

  return { service_key: null, detection_method: "none" };
}

// ─── SOR-T-202: k_mask bit validation ─────────────────────────────────────────

function docExists(serviceKey: string, dt: DocType): boolean {
  try {
    const dir = dt === "todo" ? TODOS_DIR : PROPOSALS_DIR;
    return readdirSync(dir).some(f => f.startsWith(`${serviceKey}--${dt}--`));
  } catch { return false; }
}

function probeKMaskBits(serviceKey: string, kmask: number, items: ProbeItem[]): void {
  for (let bit = 0; bit < BIT_TO_DOCTYPE.length; bit++) {
    if ((kmask & (1 << bit)) === 0) continue; // only probe claimed bits
    const dt = BIT_TO_DOCTYPE[bit];
    if (!docExists(serviceKey, dt)) {
      items.push({
        service_key: serviceKey,
        bit,
        claim:    `k_mask bit ${bit} (${dt}) = 1`,
        actual:   `no ${serviceKey}--${dt}--formal--*.md found`,
        severity: "HIGH",
        detail:   `k_mask overclaims — bit ${bit} set but ${dt} doc absent`,
      });
    }
  }
}

// ─── SOR-T-203: can_do / can_answer sync check ────────────────────────────────

function probeCanDoSync(
  serviceKey: string,
  codex: Record<string, unknown>,
  svcEntry: Record<string, unknown> | null,
  items: ProbeItem[]
): void {
  if (!svcEntry) return;

  const codexDo  = (codex.can_do      as string[] | undefined) ?? [];
  const svcDo    = (svcEntry.can_do   as string[] | undefined) ?? [];
  const codexAns = (codex.can_answer  as string[] | undefined) ?? [];
  const svcAns   = (svcEntry.can_answer as string[] | undefined) ?? [];

  const overclaims    = codexDo.filter(c => !svcDo.includes(c));
  const overclaimsAns = codexAns.filter(c => !svcAns.includes(c));
  const underclaims   = [...svcDo.filter(c => !codexDo.includes(c)), ...svcAns.filter(c => !codexAns.includes(c))];

  for (const cap of overclaims) {
    items.push({
      service_key: serviceKey, bit: null,
      claim:    `codex.json can_do: "${cap}"`,
      actual:   `absent from services.json can_do`,
      severity: "MEDIUM",
      detail:   `codex overclaims can_do — sync with services.json`,
    });
  }
  for (const cap of overclaimsAns) {
    items.push({
      service_key: serviceKey, bit: null,
      claim:    `codex.json can_answer: "${cap}"`,
      actual:   `absent from services.json can_answer`,
      severity: "MEDIUM",
      detail:   `codex overclaims can_answer — sync with services.json`,
    });
  }
  if (underclaims.length > 0) {
    items.push({
      service_key: serviceKey, bit: null,
      claim:    `services.json declares: ${underclaims.join(", ")}`,
      actual:   `these capabilities absent from codex.json`,
      severity: "MEDIUM",
      detail:   `codex underclaims — add missing capabilities`,
    });
  }
}

// ─── Main export ───────────────────────────────────────────────────────────────

export function runProbe(
  sessionId:  string,
  serviceKey: string,
  codex:      Record<string, unknown>,
  svcEntry:   Record<string, unknown> | null
): ProbeResult {
  const items: ProbeItem[] = [];
  const kmask = (codex.k_mask as number | undefined) ?? 0;

  probeKMaskBits(serviceKey, kmask, items);
  probeCanDoSync(serviceKey, codex, svcEntry, items);

  return {
    session_id:   sessionId,
    service_key:  serviceKey,
    probed_at:    new Date().toISOString(),
    items,
    high_count:   items.filter(i => i.severity === "HIGH").length,
    medium_count: items.filter(i => i.severity === "MEDIUM").length,
  };
}
