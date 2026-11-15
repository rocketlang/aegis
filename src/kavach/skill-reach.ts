// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.
//
// Skill reach — a skill describes the work; the host grants the access. A skill that carries a SKILL.needs.json
// (schema skill-needs-v1) beside its SKILL.md declares what it needs: tools, where it reads and writes, what it must
// never touch, network use, outward acts, shell commands it may not run. This module reads Claude Code session logs
// and, for every window in which such a skill was active, compares each tool call with that declaration.
//
// OBSERVE ONLY. It blocks nothing, changes nothing, installs nothing. A declaration states intent; the report says
// what the logs show. A line stays OUTSIDE even when the person's prompt asked for that act: the prompt is quoted
// for a person to judge, never used to relabel the line.
//
// Window: from the skill's start (the Skill tool call, or the "Base directory for this skill:" message a typed
// /<skill> produces) to the next prompt from a person, or another skill's start. Work the same prompt asked for
// besides the skill is counted against it.
// Not seen: subagent logs; writes made inside a script body (python, node -e) are NOT CHECKED, never passed.
// Same host: a root process can rewrite the logs, the needs files and the report.
//
// Differences from a home-grown watcher worth knowing: needs files are also read from installed plugins, a
// {{port:name}} rule needs a ports file (--ports), and times print in the machine's own zone (or --tz).

import { readFileSync, readdirSync, statSync, existsSync, createReadStream } from "fs";
import { join, resolve, isAbsolute, basename } from "path";
import { createInterface } from "readline";
import { homedir, tmpdir } from "os";

export type Needs = {
  schema: string; skill: string; act: string; network: string;
  tools: string[]; read_paths: string[]; write_paths: string[]; forbid_paths: string[]; outward_acts: string[];
  bash?: { forbid?: { re: string; why: string; raw?: boolean }[]; commit_paths_in_write_scope?: boolean };
};
export type Compiled = Needs & { dir: string; forbidRe: { re: RegExp; why: string; raw: boolean }[] };
export type Finding = { ts: string; what: string };
export type Window = { skill: string; dir: string; file: string; session: string; start: string; prompt: string; calls: number; outside: Finding[]; unchecked: Finding[] };

const HOME = homedir();

export function parseSince(s: string, now = Date.now()): number | null {
  const m = /^(\d+)([dhm])$/.exec(s);
  if (m) return now - Number(m[1]) * ({ d: 864e5, h: 36e5, m: 6e4 } as Record<string, number>)[m[2]];
  const t = Date.parse(s);
  return Number.isNaN(t) ? null : t;
}

// ---- needs files ----------------------------------------------------------------------------------------------
// Portable paths (a public skill is installed anywhere): {project} = the folder the session works in at that call,
// {skill} = the skill's own folder, {home} = the home folder, {tmp} = the system temp folder. Expanded per call.
const TOKEN_RE = /^\{(project|skill|home|tmp)\}(\/|$)/;

export function validateNeeds(n: any, expectedName?: string): string[] {
  const errs: string[] = [];
  if (!n || typeof n !== "object") return ["not an object"];
  if (n.schema !== "skill-needs-v1") errs.push('schema must be "skill-needs-v1"');
  if (typeof n.skill !== "string" || !n.skill) errs.push("skill: a name");
  if (expectedName !== undefined && n.skill !== expectedName) errs.push(`skill "${n.skill}" does not match its folder "${expectedName}"`);
  for (const k of ["tools", "read_paths", "write_paths", "forbid_paths", "outward_acts"]) if (!Array.isArray(n[k]) || n[k].some((x: unknown) => typeof x !== "string")) errs.push(`${k}: a list of strings`);
  if (!["read", "local-write", "act"].includes(n.act)) errs.push("act: read | local-write | act");
  if (!["none", "fetch-only", "any"].includes(n.network)) errs.push("network: none | fetch-only | any");
  const paths = [...(n.read_paths ?? []), ...(n.write_paths ?? []), ...(n.forbid_paths ?? [])].filter((p: unknown) => typeof p === "string");
  for (const p of paths) if (!isAbsolute(p) && !TOKEN_RE.test(p)) errs.push(`path neither absolute nor starting with {project} {skill} {home} {tmp}: ${p}`);
  for (const p of paths) if (/\{(?!project\}|skill\}|home\}|tmp\})/.test(p)) errs.push(`unknown token in ${p}`);
  for (const f of n.bash?.forbid ?? []) {
    try { new RegExp(f.re); } catch { errs.push(`bad regex: ${f.re}`); }
    if (!f.why) errs.push(`forbid rule without why: ${f.re}`);
    if (f.raw !== undefined && typeof f.raw !== "boolean") errs.push(`raw: true | false (${f.re})`);
  }
  if (n.act === "read" && n.write_paths?.length) errs.push('act "read" with write_paths');
  return errs;
}

// {{port:name}} in a rule is read from a ports file the user names (--ports), never written as a literal.
const findPort = (o: any, k: string): number | undefined => {
  if (!o || typeof o !== "object") return undefined;
  if (typeof o[k] === "number") return o[k];
  for (const v of Object.values(o)) { const r = findPort(v, k); if (r !== undefined) return r; }
  return undefined;
};
export function compileNeeds(n: Needs, dir: string, ports: unknown = {}): Compiled {
  const forbidRe = (n.bash?.forbid ?? []).map((x) => ({
    re: new RegExp(x.re.replace(/\{\{port:(\w+)\}\}/g, (_m, k) => { const p = findPort(ports, k); if (p === undefined) throw new Error(`port ${k} not in the ports file`); return String(p); })),
    why: x.why, raw: !!x.raw,
  }));
  return { ...n, dir, forbidRe };
}

/** Folders that may hold a skill with a needs file: ~/.claude/skills/<name>/ and installed plugins
 *  (~/.claude/plugins/cache/<marketplace>/<plugin>/<version>/, a plugin that is one root SKILL.md). */
export function findNeedsFiles(skillsDirs: string[], pluginCache?: string): { file: string; dir: string; name: string }[] {
  const out: { file: string; dir: string; name: string }[] = [];
  for (const sd of skillsDirs) {
    if (!existsSync(sd)) continue;
    for (const d of readdirSync(sd)) { const f = join(sd, d, "SKILL.needs.json"); if (existsSync(f)) out.push({ file: f, dir: join(sd, d), name: d }); }
  }
  if (pluginCache && existsSync(pluginCache)) {
    for (const m of readdirSync(pluginCache)) for (const p of safeDirs(join(pluginCache, m))) {
      // newest version folder only: an update leaves the old one behind
      const vers = safeDirs(join(pluginCache, m, p)).map((v) => join(pluginCache, m, p, v)).filter((v) => existsSync(join(v, "SKILL.needs.json")));
      vers.sort((a, b) => statSync(b).mtimeMs - statSync(a).mtimeMs);
      if (vers[0]) out.push({ file: join(vers[0], "SKILL.needs.json"), dir: vers[0], name: p });
    }
  }
  return out;
}
const safeDirs = (d: string): string[] => { try { return readdirSync(d).filter((x) => { try { return statSync(join(d, x)).isDirectory(); } catch { return false; } }); } catch { return []; } };

export function loadNeeds(found: { file: string; dir: string; name: string }[], ports: unknown = {}, only?: string): { needs: Record<string, Compiled>; invalid: string[] } {
  const needs: Record<string, Compiled> = {}; const invalid: string[] = [];
  for (const f of found) {
    if (only && f.name !== only) continue;
    let n: any;
    try { n = JSON.parse(readFileSync(f.file, "utf8")); } catch { invalid.push(`${f.file}: not JSON`); continue; }
    const errs = validateNeeds(n, f.name);
    if (errs.length) { invalid.push(`${f.file}: ${errs.join("; ")}`); continue; }
    if (needs[n.skill]) { invalid.push(`${f.file}: a second needs file for "${n.skill}" (first: ${needs[n.skill].dir}); the first is used`); continue; }
    try { needs[n.skill] = compileNeeds(n, f.dir, ports); } catch (e) { invalid.push(`${f.file}: ${(e as Error).message}`); }
  }
  return { needs, invalid };
}

const expandPath = (p: string, ctx: { project?: string; skill?: string }) =>
  p.replace(TOKEN_RE, (_m, t: string, sl: string) => ({ project: ctx.project ?? "/nonexistent-project", skill: ctx.skill ?? "/nonexistent-skill", home: HOME, tmp: tmpdir() } as Record<string, string>)[t] + sl);
export function expandNeeds(n: Compiled, ctx: { project?: string; skill?: string }): Compiled {
  if (![...n.read_paths, ...n.write_paths, ...n.forbid_paths].some((p) => TOKEN_RE.test(p))) return n;
  return { ...n, read_paths: n.read_paths.map((p) => expandPath(p, ctx)), write_paths: n.write_paths.map((p) => expandPath(p, ctx)), forbid_paths: n.forbid_paths.map((p) => expandPath(p, ctx)) };
}

// ---- path matching --------------------------------------------------------------------------------------------
const globRe = (g: string) => new RegExp("^" + g.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*\*/g, "\0").replace(/\*/g, "[^/]*").replace(/\0/g, ".*") + "$");
const inAny = (p: string, globs: string[]) => globs.some((g) => globRe(g).test(p) || globRe(g.replace(/\/\*\*$/, "")).test(p));

// ---- Bash, read statically ------------------------------------------------------------------------------------
// Rough shell reading: heredoc bodies removed (they are data, not commands); quoted strings blanked for redirects
// and pathspecs; rules tested one command segment at a time.
const stripHeredocs = (c: string) => c.replace(/<<-?\s*(['"]?)(\w+)\1([^\n]*)\n[\s\S]*?\n\s*\2(?=\s*(\n|$))/g, (_m, _q, _t, rest) => `<<HEREDOC${rest}`);
const blankQuotes = (c: string) => c.replace(/\$'(?:[^'\\]|\\.)*'/g, "'Q'").replace(/'[^']*'/g, "'Q'").replace(/"(?:[^"\\]|\\.)*"/g, '"Q"');
// a leading ( { env VAR=x nohup time sudo command exec, or VAR=x, is taken off so rules see the command itself
const lead = (s: string) => { let t = s.replace(/^[\s({]+/, ""), u: string; while ((u = t.replace(/^(?:(?:env|nohup|time|sudo|command|exec|xargs)\s+|[A-Za-z_]\w*=\S*\s+)/, "")) !== t) t = u; return t; };
const segments = (c: string) => c.split(/\|\||&&|[;|\n]/).map((s) => lead(s.trim())).filter(Boolean);

export function bashChecks(cmd0: string, cwd: string | undefined, n: Compiled): { hits: string[]; unchecked: string[] } {
  const hits: string[] = [], unchecked: string[] = [];
  const cmd = stripHeredocs(cmd0);
  // variables assigned to a literal earlier in the same command (M=/tmp/x; cat > $M) are resolved; others stay unresolved
  const vars: Record<string, string> = {};
  for (const m of cmd.matchAll(/(?:^|[;&\s])([A-Za-z_]\w*)=(?:"([^"$`]*)"|'([^']*)'|([^\s;&|`$'"]+))(?=[\s;&|]|$)/g)) vars[m[1]] = m[2] ?? m[3] ?? m[4];
  const sub = (t: string) => t.replace(/\$\{?([A-Za-z_]\w*)\}?/g, (x, v) => vars[v] ?? x);
  const bare = blankQuotes(cmd.replace(/"(\$\{?[A-Za-z_]\w*\}?[^"$`\s]*)"/g, (x, inner) => { const v = /\$\{?([A-Za-z_]\w*)/.exec(inner); return v && vars[v[1]] !== undefined ? sub(inner) : x; }));
  const segQ = segments(cmd), segB = segments(bare);
  // a raw rule sees each segment before env / VAR=x prefixes are taken off (EDIT_HEAT=off node ...)
  const segRaw = cmd.split(/\|\||&&|[;|\n]/).map((x) => x.trim()).filter(Boolean);
  for (const f of n.forbidRe) if ((f.raw ? segRaw : segQ).some((s) => f.re.test(s))) hits.push(`bash: ${f.why}`);
  const cd = /(?:^|[;&|]\s*)cd\s+([^\s;&|]+)/.exec(bare);
  const base = cd && !/\$/.test(cd[1]) ? resolve(cwd ?? "/", cd[1].replace(/^~(?=\/|$)/, HOME)) : cwd;
  const abs = (p: string) => resolve(base ?? "/", p.replace(/^~(?=\/)/, HOME));
  const targets: string[] = [];
  for (const s of segB) {
    for (const m of s.matchAll(/(?:^|[^0-9&<>=-])>>?\s*([^\s;&|)<>]+)/g)) if (!/^(&\d|\/dev\/(null|stderr|stdout))$/.test(m[1])) targets.push(m[1]);
    for (const m of s.matchAll(/^\s*tee\s+(?:-a\s+)?([^\s;&|)]+)/g)) targets.push(m[1]);
    // cp / mv / install / ln write their last operand (or the -t folder); mkdir and touch write every operand
    const w = s.split(/\s+/).filter(Boolean);
    if (/^(cp|mv|install|ln)$/.test(w[0])) {
      const t = w.indexOf("-t");
      const ops = w.slice(1).filter((x, i, a) => !x.startsWith("-") && a[i - 1] !== "-t" && !/^[<>]/.test(x));
      if (t > 0 && w[t + 1]) targets.push(w[t + 1]); else if (ops.length >= 2) targets.push(ops[ops.length - 1]);
    } else if (/^(mkdir|touch)$/.test(w[0])) {
      // the value after touch -r/-d/-t or mkdir -m is a reference file, a date or a mode, not a target
      const takesArg = w[0] === "touch" ? /^-[a-z]*[rdt]$/ : /^-[a-z]*m$/;
      w.slice(1).forEach((x, i, a) => { if (!x.startsWith("-") && !/^[<>]/.test(x) && !(i > 0 && takesArg.test(a[i - 1]))) targets.push(x); });
    }
  }
  for (const t0 of targets) {
    const t = sub(t0);
    if (/\$|^["']Q["']$/.test(t)) { unchecked.push("bash: write target named through a variable or quotes"); continue; }
    const p = abs(t);
    if (!inAny(p, n.write_paths)) hits.push(`bash: writes ${p}`);
  }
  if (/\b(python3?|node|bun|perl|ruby)\b[^\n]*(\s-\s|\s-e\s|<<)/.test(cmd0) && /(open\([^)]*['"]w|writeFile|\.write\(|unlink|rmSync)/.test(cmd0)) unchecked.push("bash: a write inside a script body");
  if (n.bash?.commit_paths_in_write_scope) {
    for (const s of segB) for (const m of s.matchAll(/^\s*git\s+(?:-C\s+(\S+)\s+)?(add|commit)\b(.*)$/g)) {
      const repoBase = m[1] ? abs(m[1]) : base; const rest = m[3].replace(/\s\d?>.*$|\s<.*$/, "");
      let paths: string;
      if (m[2] === "commit") {
        const i = rest.indexOf(" -- ");
        if (i < 0) { if (/\s-[a-zA-Z]*a\b|\s--all\b/.test(rest)) hits.push("bash: git commit -a"); else unchecked.push("bash: git commit without a pathspec (commits the shared index)"); continue; }
        paths = rest.slice(i + 4);
      } else paths = rest.replace(/\s-[-\w]+/g, " ");
      for (const p of sub(paths).trim().split(/\s+/).filter(Boolean)) {
        if (/^["']Q["']$/.test(p)) { unchecked.push(`bash: git ${m[2]} path in quotes`); continue; }
        if (/\$/.test(p)) { unchecked.push(`bash: git ${m[2]} paths named through a variable`); continue; }
        const ap = resolve(repoBase ?? "/", p.replace(/^["']|["']$/g, ""));
        if (!inAny(ap, n.write_paths)) hits.push(`bash: git ${m[2]} ${ap}`);
      }
    }
  }
  return { hits, unchecked };
}

// Tools that act outward; a skill must name the act in outward_acts or the call is OUTSIDE.
const OUTWARD = [
  { act: "mail", re: /(Gmail|gmail|Mail|mail).*(send|reply|forward|draft)/ },
  { act: "publish", re: /^Artifact$|(publish|post|upload)/i },
  { act: "message", re: /^(SendMessage|PushNotification|SendToProject|SendToProjectContext)$|whatsapp|telegram|slack/i },
  { act: "schedule", re: /^(CronCreate|RemoteTrigger|ScheduleWakeup)$|Calendar.*(create|update|delete|respond)/ },
];

/** One tool call against one (expanded) declaration. */
export function checkCall(tu: { name: string; input?: any }, cwd: string | undefined, n: Compiled): { outside: string[]; unchecked: string[] } {
  const name = tu.name, inp = tu.input ?? {};
  const out = { outside: [] as string[], unchecked: [] as string[] };
  if (!n.tools.includes(name)) out.outside.push(`tool not declared: ${name}`);
  const p = inp.file_path ?? inp.notebook_path ?? inp.path;
  if (p && typeof p === "string") {
    const ap = resolve(cwd ?? "/", p);
    if (inAny(ap, n.forbid_paths)) out.outside.push(`${name}: forbidden path ${ap}`);
    if (["Write", "Edit", "NotebookEdit"].includes(name) && !inAny(ap, n.write_paths)) out.outside.push(`${name}: writes ${ap}`);
    if (["Read", "Grep", "Glob"].includes(name) && !inAny(ap, n.read_paths)) out.outside.push(`${name}: reads ${ap}`);
  }
  if (name === "Bash" && typeof inp.command === "string") {
    const { hits, unchecked } = bashChecks(inp.command, cwd, n);
    out.outside.push(...hits); out.unchecked.push(...unchecked);
    for (const f of n.forbid_paths) {
      const root = f.replace(/\/\*\*$/, "");
      const tail = root.startsWith(HOME + "/") ? root.slice(HOME.length + 1) : null;
      if (inp.command.includes(root) || (tail && new RegExp(`(^|[\\s'"=/~}])${tail.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(/|\\s|$|['"])`).test(inp.command))) out.outside.push(`Bash: names forbidden path ${root}`);
    }
    if (!n.outward_acts.includes("mail") && n.forbidRe.every((f) => f.why !== "outward mail")) out.unchecked.push("bash: no outward-mail rule declared");
  }
  const outward = OUTWARD.find((o) => o.re.test(name));
  if (outward && !n.outward_acts.includes(outward.act)) out.outside.push(`outward act not declared: ${outward.act} (${name})`);
  if (n.network === "none" && ["WebFetch", "WebSearch"].includes(name)) out.outside.push(`${name}: network use, declared none`);
  return out;
}

// ---- session logs ---------------------------------------------------------------------------------------------
export function listLogs(projectsDir: string, since: number): string[] {
  const files: string[] = [];
  for (const d of existsSync(projectsDir) ? readdirSync(projectsDir) : []) {
    const dir = join(projectsDir, d);
    try { if (!statSync(dir).isDirectory()) continue; } catch { continue; }
    for (const f of readdirSync(dir)) if (f.endsWith(".jsonl")) { const fp = join(dir, f); try { if (statSync(fp).mtimeMs >= since) files.push(fp); } catch { /* gone */ } }
  }
  return files;
}

const textOf = (c: any): string => typeof c === "string" ? c : Array.isArray(c) ? c.filter((x: any) => x.type === "text").map((x: any) => x.text).join("\n") : "";
const isToolResult = (c: any) => Array.isArray(c) && c.some((x: any) => x.type === "tool_result");

/** Which declared skill a "Base directory for this skill:" path or a Skill tool name refers to. */
function skillOfDir(dir: string, needs: Record<string, Compiled>): string | undefined {
  const r = resolve(dir);
  for (const [s, n] of Object.entries(needs)) if (resolve(n.dir) === r) return s;
  const b = basename(r);
  return needs[b] ? b : undefined;
}
function skillOfTool(skill: unknown, needs: Record<string, Compiled>): string | undefined {
  const s = String(skill ?? "");
  if (needs[s]) return s;
  // a plugin's skill is named <plugin>:<skill>; only <name>:<name> (a plugin that is that one skill) maps to <name>
  const m = /^([^:]+):\1$/.exec(s);
  return m && needs[m[1]] ? m[1] : undefined;
}

export async function scanLogs(files: string[], needs: Record<string, Compiled>, since: number): Promise<{ windows: Window[]; unreadable: number }> {
  const windows: Window[] = []; let unreadable = 0;
  for (const fp of files) {
    let active: Window | null = null; let lastPrompt = "";
    const close = () => { if (active && active.calls) windows.push(active); active = null; };
    const open = (skill: string, dir: string, d: any) => { close(); active = { skill, dir, file: fp, session: d.sessionId, start: d.timestamp, prompt: lastPrompt, calls: 0, outside: [], unchecked: [] }; };
    try {
      const rl = createInterface({ input: createReadStream(fp), crlfDelay: Infinity });
      for await (const line of rl) {
        if (!line.includes('"type":"user"') && !line.includes('"type":"assistant"')) continue;
        let d: any; try { d = JSON.parse(line); } catch { continue; }
        const inRange = Date.parse(d.timestamp ?? "") >= since;
        if (d.type === "user" && !isToolResult(d.message?.content)) {
          const t = textOf(d.message?.content);
          const m = /^Base directory for this skill: (\S+)/.exec(t);
          if (m) { const s = skillOfDir(m[1], needs); if (s && (active as Window | null)?.skill !== s) open(s, m[1], d); continue; }
          if (/^<command-/.test(t.trim())) { const nm = /<command-name>([^<]*)</.exec(t)?.[1] ?? "", a = /<command-args>([^<]*)</.exec(t)?.[1] ?? ""; lastPrompt = `${nm} ${a}`.trim(); continue; }
          if (d.isMeta || /^<(system-reminder|task-notification|local-command)/.test(t.trim())) continue;
          lastPrompt = t; close(); continue; // a prompt from a person ends the window
        }
        if (d.type === "assistant" && Array.isArray(d.message?.content)) {
          for (const c of d.message.content) {
            if (c.type !== "tool_use") continue;
            if (c.name === "Skill") {
              const sk = skillOfTool(c.input?.skill, needs);
              if (sk && (active as Window | null)?.skill !== sk) { open(sk, needs[sk].dir, d); continue; }
              close(); continue; // another skill takes over (or the same one again): stop attributing to this one
            }
            const a = active as Window | null;
            if (!a || !inRange) continue;
            a.calls++;
            const r = checkCall(c, d.cwd, expandNeeds(needs[a.skill], { project: d.cwd, skill: a.dir }));
            for (const o of r.outside) a.outside.push({ ts: d.timestamp, what: o });
            for (const u of r.unchecked) a.unchecked.push({ ts: d.timestamp, what: u });
          }
        }
      }
    } catch { unreadable++; }
    close();
  }
  return { windows, unreadable };
}

// ---- report ---------------------------------------------------------------------------------------------------
// The opening prompt, quoted so a person can judge whether it asked for an OUTSIDE act. Pasted text is someone
// else's words (untrusted data): it is replaced by a marker; only the person's own words are quoted.
export const quotePrompt = (t: string) => {
  const one = String(t ?? "").replace(/<pasted_content[^>]*>[\s\S]*?<\/pasted_content[^>]*>/g, "[pasted text]").replace(/<pasted_content[\s\S]*$/, "[pasted text]").replace(/\s+/g, " ").trim();
  return one ? `«${one.length > 160 ? one.slice(0, 157) + "..." : one}»` : "(no prompt found before the window)";
};

/** Local time of the machine, labelled with its zone (the logs store UTC). */
export function localTime(iso: string | undefined, tz?: string): string {
  const ms = Date.parse(iso ?? "");
  if (Number.isNaN(ms)) return "????-??-?? ??:??:??";
  const f = new Intl.DateTimeFormat("en-CA", { timeZone: tz, year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
  const p = Object.fromEntries(f.formatToParts(new Date(ms)).map((x) => [x.type, x.value]));
  return `${p.year}-${p.month}-${p.day} ${p.hour === "24" ? "00" : p.hour}:${p.minute}:${p.second}`;
}
export const zoneLabel = (tz?: string) => tz ?? Intl.DateTimeFormat().resolvedOptions().timeZone ?? "local";

export type Report = { text: string; exit: 0 | 1 | 2; outside: number; unchecked: number; windows: Window[] };
export function formatReport(o: { windows: Window[]; unreadable: number; invalid: string[]; skills: string[]; logs: number; sinceSpec: string; now?: Date; tz?: string }): Report {
  const tz = o.tz, zone = zoneLabel(tz);
  const L: string[] = [];
  const outsideN = o.windows.reduce((a, w) => a + w.outside.length, 0), uncheckedN = o.windows.reduce((a, w) => a + w.unchecked.length, 0);
  L.push(`Skill reach watch, ${localTime((o.now ?? new Date()).toISOString(), tz).slice(0, 16)} ${zone}. ${o.skills.length} skill(s) declare their needs (${o.skills.join(", ") || "none"}); ${o.logs} session log(s) since ${o.sinceSpec}.`);
  L.push(`${o.windows.length} window(s) where a declared skill was active; ${o.windows.reduce((a, w) => a + w.calls, 0)} tool call(s); OUTSIDE ${outsideN}; NOT CHECKED ${uncheckedN}.`);
  const byStart = [...o.windows].sort((a, b) => (Date.parse(a.start) || 0) - (Date.parse(b.start) || 0));
  for (const w of byStart) {
    const head = `${w.skill} · ${localTime(w.start, tz).slice(0, 16)} · session ${String(w.session).slice(0, 8)} · ${w.calls} call(s)`;
    if (!w.outside.length && !w.unchecked.length) { L.push(`INSIDE       ${head}`); continue; }
    L.push(`${w.outside.length ? "OUTSIDE     " : "NOT CHECKED "} ${head}`);
    L.push(`    opened by    ${quotePrompt(w.prompt)} (quoted for a person to judge; the watcher does not)`);
    for (const f of w.outside) L.push(`    outside      ${localTime(f.ts, tz).slice(11, 19)}  ${f.what}`);
    const uc: Record<string, number> = {}; for (const u of w.unchecked) uc[u.what] = (uc[u.what] ?? 0) + 1;
    for (const [k, v] of Object.entries(uc)) L.push(`    not checked  ${k} (${v})`);
  }
  for (const l of o.invalid) L.push(`INVALID      ${l}`);
  if (o.unreadable) L.push(`COULD NOT CHECK  ${o.unreadable} log(s) unreadable`);
  L.push("Observe only: blocks nothing, changes nothing. A window runs from the skill's start to the next prompt, so work the");
  L.push("same prompt asked for besides the skill is counted against it. Subagent logs and writes inside script bodies are not read.");
  const exit = outsideN ? 1 : (uncheckedN || o.invalid.length || o.unreadable) ? 2 : 0;
  return { text: L.join("\n") + "\n", exit, outside: outsideN, unchecked: uncheckedN, windows: o.windows };
}
