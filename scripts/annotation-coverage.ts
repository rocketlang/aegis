#!/usr/bin/env bun
// SPDX-License-Identifier: AGPL-3.0-only
// BMI-T014 — annotation coverage of aegis's enforcement points (2026-10-29, founder: "build T014").
//
// An ENFORCEMENT POINT is a source line where a guard refuses, blocks or holds:
//   a verdict / action / decision of REFUSE, BLOCK, QUARANTINE, block or deny · `allowed: false` ·
//   `ask: true` (held for a person) · `process.exit(2)` in a hook (cli/commands/check-*.ts, hooks/): a Claude
//   Code hook blocking a tool call. Elsewhere exit 2 is a CLI usage error, not a point.
// Type declarations (a union such as "PERMIT" | "REFUSE"), comments and tests are not points.
// A point is ANNOTATED when an `@rule:` comment is on its line or within the WINDOW lines above it (aegis
// puts one rule comment over a block of checks). The window is a convention, not proof that the rule named
// is the one enforced: this measures whether a point cites a law at all (FP-004), not whether it cites the
// right one.
// A second, wider measure: CITED, when the point names a rule any way aegis does it: an @rule: comment, a
// `law:` field (the outward permissives), or a refusal text that begins with a rule id ("ASG-003: ...", the
// ANU-006 convention). Forja's PROOF coverage counts @rule: only, so the strict figure is the one for T014.
//
//   bun scripts/annotation-coverage.ts [src-dir] [--json] [--list]     exit 0 ≥ 90% · 1 below · 3 broke
import { readdirSync, readFileSync, statSync } from "fs";
import { join, relative } from "path";

export const WINDOW = 15;
export const TARGET = 0.9;

const POINT = /\b(verdict|action|decision)\s*:\s*["'](REFUSE|BLOCK|QUARANTINE|block|deny)["']|\ballowed\s*:\s*false\b|\bask\s*:\s*true\b/;
const HOOK_BLOCK = /\bprocess\.exit\(\s*2\s*\)/;
const isHook = (file: string) => /(^|\/)cli\/commands\/check-[^/]+\.ts$|(^|\/)hooks\//.test(file);
const TYPE_UNION = /["'][A-Z_]+["']\s*\|\s*["'][A-Z_]+["']/;     // "PERMIT" | "REFUSE": a type, not a decision
const COMMENT = /^\s*(\/\/|\*|\/\*)/;
const RULE = /@rule:/;
const CITE = /@rule:|\blaw\s*:\s*["'`][A-Z]|["'`][A-Z]{2,}(-[A-Z]{1,4})?-\d{3}\b/;

export interface Point { file: string; line: number; text: string; annotated: boolean; cited: boolean }

export function scanText(file: string, text: string): Point[] {
  const lines = text.split("\n"), out: Point[] = [];
  lines.forEach((l, i) => {
    if (COMMENT.test(l) || TYPE_UNION.test(l) || !(POINT.test(l) || (isHook(file) && HOOK_BLOCK.test(l)))) return;
    if (/^\s*(type|interface)\b/.test(l) || /:\s*(boolean|string)\s*[;,]/.test(l)) return;
    const from = Math.max(0, i - WINDOW);
    const window = lines.slice(from, i + 1);
    const annotated = window.some((x) => RULE.test(x));
    out.push({ file, line: i + 1, text: l.trim().slice(0, 140), annotated, cited: annotated || window.some((x) => CITE.test(x)) });
  });
  return out;
}

export function scanDir(root: string): Point[] {
  const out: Point[] = [];
  const walk = (d: string) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, e.name);
      if (e.isDirectory()) { if (e.name !== "node_modules") walk(p); }
      else if (e.name.endsWith(".ts") && !e.name.endsWith(".test.ts") && !e.name.endsWith(".d.ts")) out.push(...scanText(relative(root, p), readFileSync(p, "utf8")));
    }
  };
  walk(root);
  return out;
}

if (import.meta.main) {
  const args = process.argv.slice(2);
  const dir = args.find((a) => !a.startsWith("--")) ?? join(import.meta.dir, "..", "src");
  try { if (!statSync(dir).isDirectory()) throw new Error("not a directory"); } catch (e: any) { console.log(`BROKE — ${dir}: ${e?.message ?? e}`); process.exit(3); }
  const pts = scanDir(dir), ann = pts.filter((p) => p.annotated).length, pct = pts.length ? ann / pts.length : 1;
  const cit = pts.filter((p) => p.cited).length;
  const byFile = new Map<string, { n: number; a: number }>();
  for (const p of pts) { const f = byFile.get(p.file) ?? { n: 0, a: 0 }; f.n++; if (p.annotated) f.a++; byFile.set(p.file, f); }
  if (args.includes("--json")) {
    console.log(JSON.stringify({ measured_at: new Date().toISOString(), window_lines: WINDOW, target: TARGET, points: pts.length, annotated: ann, coverage: Number(pct.toFixed(4)), cited: cit, cited_coverage: Number((pts.length ? cit / pts.length : 1).toFixed(4)),
      files: [...byFile].map(([file, f]) => ({ file, points: f.n, annotated: f.a })).sort((a, b) => (b.points - b.annotated) - (a.points - a.annotated)) }, null, 2));
  } else {
    console.log(`aegis enforcement points: ${pts.length} · annotated (@rule: within ${WINDOW} lines): ${ann} · coverage ${(pct * 100).toFixed(1)}% (target ${TARGET * 100}%)`);
    console.log(`cites a rule any way (@rule:, a law: field, or a refusal text that starts with a rule id): ${cit} · ${(pts.length ? (cit / pts.length) * 100 : 100).toFixed(1)}%`);
    const worst = [...byFile].filter(([, f]) => f.a < f.n).sort((a, b) => (b[1].n - b[1].a) - (a[1].n - a[1].a)).slice(0, 12);
    if (worst.length) console.log("most unannotated:\n" + worst.map(([file, f]) => `  ${String(f.n - f.a).padStart(3)} of ${String(f.n).padStart(3)}  ${file}`).join("\n"));
    if (args.includes("--list")) console.log("\nunannotated points:\n" + pts.filter((p) => !p.annotated).map((p) => `  ${p.file}:${p.line}  ${p.text}`).join("\n"));
  }
  process.exit(pct >= TARGET ? 0 : 1);
}
