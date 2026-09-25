// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// KAVACH — CI pipeline audit (AF-T-710, INF-AFW-007).
//
// A CI runner is an UNGOVERNED host: no hook, no valve, no kernel jail binds what runs
// there. This audit does not pretend otherwise. It enforces the one thing a repo CAN
// enforce about its pipelines from the outside:
//   1. Every PUBLISH step in a workflow must be DECLARED (.github/ankr-ci-declarations.json
//      names the workflow, the artifacts, and why) — an undeclared publish FAILS the audit.
//      This is AFW-012 applied to the pipeline: the declaration is the mandate.
//   2. External hosts named in run: lines are reported against the same egress declarations
//      the box uses (informational — CI legitimately reaches build infrastructure).
//   3. `uses:` third-party actions are a SCOPED NULL (FP-018): their inner traffic is not
//      auditable from the YAML, and the report says so instead of implying coverage.

import { readFileSync, readdirSync, existsSync } from "fs";
import { join } from "path";
import { isPublishInvocation, resolvePublishArtifact } from "./publish-capability";
import { resolveTargetHosts, classifyHost, declaredHosts } from "./net-capability";

export interface CiDeclarations {
  workflows: Record<string, { publishes: string[]; reason: string }>;
}

export interface WorkflowAudit {
  workflow: string;
  /** publish steps found in run: lines, each with its declaration state */
  publishes: { line: string; kind: string; artifact: string | null; declared: boolean }[];
  /** external hosts named in run: lines that are not in the egress declarations */
  undeclaredHosts: string[];
  /** third-party actions — unauditable from YAML, reported as a scoped null */
  thirdPartyActions: string[];
}

export interface CiAuditReport {
  audits: WorkflowAudit[];
  /** the audit FAILS only on an undeclared publish — the enforceable half */
  undeclaredPublishes: number;
}

/** run: lines of a workflow, multi-line blocks flattened line-by-line. */
export function runLines(yamlText: string): string[] {
  const out: string[] = [];
  const lines = yamlText.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const m = /^\s*(?:-\s+)?run:\s*(.*)$/.exec(lines[i]);
    if (!m) continue;
    if (m[1] === "|" || m[1] === ">" || m[1] === "") {
      const baseIndent = lines[i].search(/\S/);
      for (let j = i + 1; j < lines.length; j++) {
        const ind = lines[j].search(/\S/);
        if (lines[j].trim() === "") continue;
        if (ind <= baseIndent) break;
        out.push(lines[j].trim());
      }
    } else {
      out.push(m[1]);
    }
  }
  return out;
}

export function usesActions(yamlText: string): string[] {
  const out: string[] = [];
  for (const m of yamlText.matchAll(/^\s*(?:-\s+)?uses:\s*(\S+)/gm)) {
    // first-party GitHub actions are still third-party CODE, but the audit's null is about
    // arbitrary marketplace actions; report all — the reader decides what they trust.
    out.push(m[1]);
  }
  return [...new Set(out)];
}

export function auditWorkflow(name: string, yamlText: string, decl: CiDeclarations): WorkflowAudit {
  const declared = decl.workflows[name]?.publishes ?? [];
  const publishes: WorkflowAudit["publishes"] = [];
  const hostSet = new Set<string>();
  const universe = declaredHosts();

  for (const line of runLines(yamlText)) {
    const p = isPublishInvocation(line);
    if (p.publish) {
      const artifact = resolvePublishArtifact(line);
      // A publish is declared when the workflow has ANY declaration entry and either the
      // artifact matches one of its names, or the artifact is implicit (cwd publish) and
      // the declaration names at least one artifact — the declaration IS the mandate.
      const isDeclared =
        declared.length > 0 && (artifact === null || declared.some((d) => artifact.includes(d) || d.includes(artifact)));
      publishes.push({ line, kind: p.kind!, artifact, declared: isDeclared });
    }
    for (const h of resolveTargetHosts(line)) {
      if (h && classifyHost(h, universe) === "undeclared") hostSet.add(h);
    }
  }

  return { workflow: name, publishes, undeclaredHosts: [...hostSet], thirdPartyActions: usesActions(yamlText) };
}

export function auditWorkflowsDir(dir: string, decl: CiDeclarations): CiAuditReport {
  const wfDir = join(dir, ".github", "workflows");
  const audits: WorkflowAudit[] = [];
  if (existsSync(wfDir)) {
    for (const f of readdirSync(wfDir).filter((f) => /\.ya?ml$/.test(f)).sort()) {
      audits.push(auditWorkflow(f, readFileSync(join(wfDir, f), "utf-8"), decl));
    }
  }
  const undeclaredPublishes = audits.reduce((s, a) => s + a.publishes.filter((p) => !p.declared).length, 0);
  return { audits, undeclaredPublishes };
}

export function readCiDeclarations(dir: string): CiDeclarations {
  try {
    const p = join(dir, ".github", "ankr-ci-declarations.json");
    if (existsSync(p)) return JSON.parse(readFileSync(p, "utf-8"));
  } catch { /* unreadable declares nothing */ }
  return { workflows: {} };
}

export function renderCiAudit(r: CiAuditReport): string {
  let out = "# aegis ci-audit — pipelines vs declarations (INF-AFW-007)\n\n";
  out += "> A CI runner is an ungoverned host. Enforced here: every publish step must be declared\n";
  out += "> (.github/ankr-ci-declarations.json). Egress is reported; `uses:` actions are a SCOPED NULL\n";
  out += "> — their inner traffic is not auditable from the YAML, and no coverage is implied.\n\n";
  for (const a of r.audits) {
    out += `## ${a.workflow}\n`;
    if (a.publishes.length) {
      for (const p of a.publishes) {
        out += `- publish (${p.kind}) ${p.artifact ?? "(cwd-implicit)"} — ${p.declared ? "DECLARED" : "**UNDECLARED — FAIL**"}\n    \`${p.line.slice(0, 100)}\`\n`;
      }
    } else {
      out += "- no publish steps\n";
    }
    if (a.undeclaredHosts.length) out += `- undeclared external hosts in run: lines: ${a.undeclaredHosts.join(", ")}\n`;
    if (a.thirdPartyActions.length) out += `- scoped NULL: ${a.thirdPartyActions.length} action(s) (${a.thirdPartyActions.join(", ")})\n`;
    out += "\n";
  }
  out += r.undeclaredPublishes
    ? `RESULT: FAIL — ${r.undeclaredPublishes} undeclared publish step(s). Declare them or remove them.\n`
    : "RESULT: PASS — every publish step is declared.\n";
  return out;
}
