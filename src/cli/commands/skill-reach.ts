// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// `aegis skill-reach` — what each skill did, against what its SKILL.needs.json declares. OBSERVE ONLY.
//
//   aegis skill-reach [--since 48h|7d|<ISO>] [--skill <name>] [--json] [--out <file>]
//                     [--skills <dir>]... [--plugins <dir>] [--projects <dir>] [--ports <file>] [--tz <zone>]
//   aegis skill-reach --validate          check the needs files only
//
// Reads needs files from ~/.claude/skills/<name>/ and from installed plugins (~/.claude/plugins/cache), and session
// logs from ~/.claude/projects. Exit codes: 0 every call inside its declaration · 1 at least one OUTSIDE ·
// 2 none outside, something NOT CHECKED, a needs file invalid or a log unreadable · 3 broke.
// CEILING, printed every time: subagent logs and writes inside script bodies are not read; same-host evidence.

import { readFileSync, writeFileSync } from "fs";
import { join } from "path";
import { homedir } from "os";
import { parseSince, findNeedsFiles, loadNeeds, listLogs, scanLogs, formatReport } from "../../kavach/skill-reach";

const USAGE = "usage: aegis skill-reach [--since 48h|7d|<ISO>] [--skill <name>] [--json] [--out <file>] [--skills <dir>] [--plugins <dir>] [--projects <dir>] [--ports <file>] [--tz <zone>] | --validate\n";

export default async function skillReach(args: string[]): Promise<void> {
  let code = 3;
  try {
    const val = (k: string) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : undefined; };
    const vals = (k: string) => args.flatMap((a, i) => (a === k && args[i + 1] ? [args[i + 1]] : []));
    if (args.includes("--help") || args.includes("-h")) { process.stdout.write(USAGE); code = 0; return; }
    const home = homedir();
    const skillsDirs = vals("--skills").length ? vals("--skills") : [join(home, ".claude/skills")];
    const plugins = val("--plugins") ?? (vals("--skills").length ? undefined : join(home, ".claude/plugins/cache"));
    const projects = val("--projects") ?? join(home, ".claude/projects");
    const sinceSpec = val("--since") ?? "48h";
    const since = parseSince(sinceSpec);
    if (since === null) { process.stderr.write(`bad --since: ${sinceSpec}\n${USAGE}`); code = 3; return; }
    let ports: unknown = {};
    const portsFile = val("--ports") ?? process.env.AEGIS_PORTS_FILE;
    if (portsFile) { try { ports = JSON.parse(readFileSync(portsFile, "utf8")); } catch (e) { process.stderr.write(`ports file unreadable: ${(e as Error).message}\n`); code = 3; return; } }

    const { needs, invalid } = loadNeeds(findNeedsFiles(skillsDirs, plugins), ports, val("--skill"));
    if (args.includes("--validate")) {
      for (const s of Object.keys(needs)) console.log(`VALID    ${s}`);
      for (const l of invalid) console.log(`INVALID  ${l}`);
      code = invalid.length ? 2 : 0; return;
    }
    const files = listLogs(projects, since);
    const { windows, unreadable } = await scanLogs(files, needs, since);
    const r = formatReport({ windows, unreadable, invalid, skills: Object.keys(needs), logs: files.length, sinceSpec, tz: val("--tz") });
    const out = args.includes("--json")
      ? JSON.stringify({ outside: r.outside, not_checked: r.unchecked, invalid, unreadable, windows: r.windows.map(({ file: _f, prompt: _p, ...w }) => w), observe_only: true }, null, 2) + "\n"
      : r.text;
    const outFile = val("--out");
    if (outFile) writeFileSync(outFile, out);
    process.stdout.write(out);
    code = r.exit;
  } catch (e) {
    process.stderr.write(`aegis skill-reach broke: ${(e as Error).message}\n`);
    code = 3;
  } finally {
    process.exit(code);
  }
}
