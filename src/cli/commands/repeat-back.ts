// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// `aegis repeat-back request --package <name> --version <v> --commit <sha> [--repo owner/name]`
// `aegis repeat-back approve <id>` | `deny <id> --reason "..."`   (a person, at a terminal)
// `aegis repeat-back list` | `report [--since YYYY-MM-DD]` | `verify`   [--json on each]
//
// The release record (RPB-001..006). The agent asks for one exact release; aegis reads the CI
// verdict for that commit from GitHub. A person decides by typing the act back; the verdict is
// read again at that moment and kept beside the decision, yes or no. Observe only: nothing is
// refused at publish time yet (P1b, on the founder's word).
//
// Exit: 0 done · 2 refused (not repeated back, an agent session, no terminal, already decided) ·
// 3 broke (bad arguments, GitHub unreadable, record chain broken).

import { spawnSync } from "child_process";
import { createInterface } from "readline";
import {
  type CheckRun, type Evidence, RecordBroken, decisionFor, findRequest, readRecord, recordDecision,
  recordPath, recordRequest, repeatBackPhrase, report, verdictOf,
} from "../../kavach/repeat-back";

const flag = (args: string[], k: string): string | undefined => {
  const i = args.indexOf(k);
  return i >= 0 && args[i + 1] !== undefined ? args[i + 1] : undefined;
};

// @rule:RPB-YK-001 — aegis reads the checks itself; a failure to read is "broke", never "green".
function readEvidence(repo: string, commit: string): Evidence {
  const r = spawnSync("gh", ["api", "--paginate", `repos/${repo}/commits/${commit}/check-runs`, "--jq", ".check_runs[] | {name, status, conclusion}"], { encoding: "utf8", timeout: 60_000 });
  if (r.status !== 0) throw new Error(`could not read CI checks from GitHub: ${(r.stderr || r.error?.message || "").trim().slice(0, 200)}`);
  const checks: CheckRun[] = r.stdout.split("\n").filter(Boolean).map((l) => JSON.parse(l));
  return { verdict: verdictOf(checks), checks, read_at: new Date().toISOString() };
}

function defaultRepo(): string | undefined {
  const r = spawnSync("gh", ["repo", "view", "--json", "nameWithOwner", "-q", ".nameWithOwner"], { encoding: "utf8", timeout: 30_000 });
  return r.status === 0 ? r.stdout.trim() : undefined;
}

const ask = (q: string): Promise<string> => new Promise((res) => {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  rl.question(q, (a) => { rl.close(); res(a); });
});

export default async function repeatBack(args: string[]): Promise<void> {
  const sub = args[0];
  const json = args.includes("--json");
  const out = (o: unknown, code = 0): never => {
    process.stdout.write(json ? JSON.stringify(o) + "\n" : (typeof o === "string" ? o : JSON.stringify(o, null, 2)) + "\n");
    process.exit(code);
  };
  const refuse = (why: string): never => { process.stderr.write(`refused: ${why}\n`); process.exit(2); };

  try {
    if (sub === "request") {
      const repo = flag(args, "--repo") ?? defaultRepo();
      const act = { repo: repo ?? "", package: flag(args, "--package") ?? "", version: flag(args, "--version") ?? "", commit: flag(args, "--commit") ?? "" };
      if (!act.package || !act.version || !act.commit || !act.repo) {
        process.stderr.write("usage: aegis repeat-back request --package <name> --version <v> --commit <full sha> [--repo owner/name]\n");
        process.exit(3);
      }
      const row = recordRequest(act, readEvidence(act.repo, act.commit));
      if (json) out(row);
      out(`request ${row.id}: ${repeatBackPhrase(row)} (${row.repo})\nCI at asking: ${row.evidence.verdict} (${row.evidence.checks.length} checks)\nA person decides at a terminal: aegis repeat-back approve ${row.id}   or   deny ${row.id} --reason "..."`);
    }

    if (sub === "approve" || sub === "deny") {
      const id = args[1];
      if (!id || id.startsWith("--")) { process.stderr.write(`usage: aegis repeat-back ${sub} <id>${sub === "deny" ? ' --reason "..."' : ""}\n`); process.exit(3); }
      // @rule:RPB-002 — a person's decision, at a terminal. Ceiling (RPB-YK-002): same host.
      if (process.env.CLAUDE_CODE_SESSION_ID?.trim()) refuse("a decision is the person's, at their own terminal; an agent session does not write it");
      if (!process.stdin.isTTY) refuse("a decision is taken at a terminal (stdin is not a TTY)");
      if (sub === "deny" && !flag(args, "--reason")?.trim()) refuse("a no needs a reason: --reason \"...\"");
      const rows = readRecord();
      const req = findRequest(id, rows);
      if (!req) refuse(`no request ${id}`);
      if (decisionFor(id, rows)) refuse(`request ${id} is already decided; a changed act is a new request`);
      const evidence = readEvidence(req!.repo, req!.commit); // RPB-003: the verdict now, not at asking
      process.stdout.write(`\n  ${sub === "approve" ? "RELEASE" : "REFUSE"}: ${req!.package} ${req!.version}\n  repo ${req!.repo}\n  commit ${req!.commit}\n  CI now: ${evidence.verdict}\n`);
      for (const c of evidence.checks) process.stdout.write(`    ${c.conclusion ?? c.status}  ${c.name}\n`);
      if (evidence.verdict !== "green" && sub === "approve") process.stdout.write(`  NOTE: CI is not green; a yes now is recorded as an override.\n`);
      const typed = await ask(`\n  Repeat back to ${sub}: ${repeatBackPhrase(req!)}\n  > `);
      try {
        const d = recordDecision(id, sub, typed, evidence, { by: process.env.SUDO_USER || process.env.USER || "person", reason: flag(args, "--reason") });
        out(json ? d : `recorded: ${d.decision} ${repeatBackPhrase(req!)} on CI ${d.evidence.verdict} (${recordPath()})`);
      } catch (e) {
        refuse((e as Error).message);
      }
    }

    if (sub === "list") {
      const rows = readRecord();
      const reqs = rows.filter((r) => r.type === "request");
      if (json) out(reqs.map((q) => ({ ...q, decision: decisionFor(q.id, rows) ?? null })));
      if (!reqs.length) out("no release requests");
      out(reqs.map((q) => {
        const d = decisionFor(q.id, rows);
        return `${q.id}  ${repeatBackPhrase(q as never)}  asked on CI ${q.evidence.verdict}  ${d ? `${d.decision} on CI ${d.evidence.verdict} by ${d.by}` : "OPEN"}`;
      }).join("\n"));
    }

    if (sub === "report") {
      const s = flag(args, "--since");
      const r = report(readRecord(), s ? new Date(s) : undefined);
      if (json) out(r);
      const lines = [
        `Repeat-back report${s ? ` since ${s}` : ""}: ${r.requests} request(s), ${r.decided} decided, ${r.open} open.`,
        `  confirmed ${r.counts.confirmed} (yes on green) · overrode ${r.counts.overrode} (yes on not-green) · changed ${r.counts.changed} (no on green) · agreed ${r.counts.agreed} (no on not-green)`,
        `  median wait: ${r.wait_minutes_median ?? "-"} min`,
        ...r.overrides.map((o) => `  override: ${o.act} on CI ${o.verdict}, by ${o.by}, ${o.at}`),
        `A gate that only ever confirms is a candidate for a machine check. The team rules; this report removes nothing.`,
      ];
      out(lines.join("\n"));
    }

    if (sub === "verify") {
      const rows = readRecord();
      out(json ? { ok: true, rows: rows.length } : `record intact: ${rows.length} row(s), chain unbroken (${recordPath()})`);
    }

    process.stderr.write("usage: aegis repeat-back request|approve|deny|list|report|verify  (see the header of src/cli/commands/repeat-back.ts)\n");
    process.exit(3);
  } catch (e) {
    process.stderr.write(`${e instanceof RecordBroken ? "RECORD BROKEN" : "broke"}: ${(e as Error).message}\n`);
    process.exit(3);
  }
}
