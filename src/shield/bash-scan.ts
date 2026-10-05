// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// AEGIS Shield — reading a shell command.
//
// @rule:KAV-095 what the file rules stop for the Read and Write tools they also stop when
//               the same file is named in a shell command; and a network tool is recognised
//               by the program that runs, wherever in the command it stands.
//
// A command line is split into simple commands (at ; && || | & newline, inside $( ), back
// ticks, <( ), `bash -c "…"`, `eval`, and a here-document fed to a shell). Each has a verb
// (the program, without its directory, after sudo/env/nohup/timeout/xargs…), arguments, and
// the files it redirects from and to.
//
// CEILING (state it, never round up): this reads the TEXT of a command. It does not run a
// shell. A path or program held in a variable, built by string tricks, decoded at run time,
// or inside a script file or an interpreter's own code (python -c, node -e) is not seen.
// It is a net for the plain cases, which are the common ones, not a sandbox. The kernel
// faces (file and network capability) are the layer that does not depend on the text.

import { basename } from "path";

export interface SimpleCommand {
  /** Program name without directory, lower case as written (`/usr/bin/curl` → `curl`). */
  verb: string;
  args: string[];
  /** Files read by redirection (`< file`). */
  inputs: string[];
  /** Files written by redirection (`> file`, `>> file`). */
  outputs: string[];
  /** Where an earlier `cd` or `pushd` in the same command line left the shell, as written. */
  cwd?: string;
}

const MAX_COMMAND = 200_000; // characters read; a longer command is read up to here
const MAX_DEPTH = 6;
// Shell words that stand in front of a command without being one: `then curl …`, `do cat …`.
const KEYWORDS = new Set(["if", "then", "else", "elif", "do", "while", "until", "!", "time", "coproc"]);
const SHELLS = new Set(["bash", "sh", "zsh", "dash", "ksh", "ash", "fish"]);
// Programs that run another program given as their arguments.
const WRAPPERS = new Set(["sudo", "doas", "env", "nohup", "time", "command", "exec", "nice", "ionice", "timeout", "stdbuf", "setsid", "xargs", "busybox", "builtin", "chronic", "watch", "strace", "ltrace", "unbuffer", "caffeinate", "flock"]);
// Wrapper options that take a value (so the value is not mistaken for the program).
const WRAPPER_VALUE_OPTS: Record<string, Set<string>> = {
  sudo: new Set(["-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-U", "--user", "--group", "--host", "--chdir"]),
  doas: new Set(["-u", "-C"]),
  env: new Set(["-u", "-C", "--unset", "--chdir", "-S"]),
  nice: new Set(["-n", "--adjustment"]),
  ionice: new Set(["-c", "-n", "-p"]),
  timeout: new Set(["-s", "-k", "--signal", "--kill-after"]),
  stdbuf: new Set(["-i", "-o", "-e"]),
  xargs: new Set(["-I", "-n", "-P", "-d", "-E", "-L", "-s", "-a", "--max-args", "--max-procs", "--delimiter", "--arg-file"]),
  watch: new Set(["-n", "-d", "--interval"]),
  strace: new Set(["-o", "-e", "-p", "-s"]),
  flock: new Set(["-w", "-E", "--timeout"]),
};

/** Pull `$( … )`, `<( … )`, `>( … )` and back-tick bodies out of the text. */
function liftSubstitutions(text: string, bodies: string[]): string {
  let out = "";
  let i = 0;
  let single = false;
  // Looking for the matching ")" is paid for from a budget, so a command made of unclosed
  // "$(" cannot make this quadratic. When the budget is spent the rest is read as plain text.
  let budget = text.length * 4 + 1024;
  while (i < text.length) {
    const ch = text[i];
    if (single) { out += ch; if (ch === "'") single = false; i++; continue; }
    if (ch === "\\" && i + 1 < text.length) { out += ch + text[i + 1]; i += 2; continue; }
    if (ch === "'") { single = true; out += ch; i++; continue; }
    if (ch === "`") {
      const end = text.indexOf("`", i + 1);
      if (end === -1) { out += ch; i++; continue; }
      bodies.push(text.slice(i + 1, end));
      out += " _SUBST_ ";
      i = end + 1;
      continue;
    }
    if (budget > 0 && (ch === "$" || ch === "<" || ch === ">") && text[i + 1] === "(" && text[i + 2] !== "(") {
      let depth = 1;
      let j = i + 2;
      let q: string | null = null;
      for (; j < text.length && depth > 0; j++) {
        const c = text[j];
        if (q) { if (c === q) q = null; else if (c === "\\" && q === '"') j++; continue; }
        if (c === "\\") { j++; continue; }
        if (c === "'" || c === '"') q = c;
        else if (c === "(") depth++;
        else if (c === ")") depth--;
      }
      budget -= j - i;
      if (depth === 0) {
        bodies.push(text.slice(i + 2, j - 1));
        out += " _SUBST_ ";
        i = j;
        continue;
      }
    }
    out += ch;
    i++;
  }
  return out;
}

type Tok = { t: "word"; v: string } | { t: "op"; v: string };

/** Words and operators. Quotes are removed; an operator inside quotes stays part of the word. */
function tokenize(text: string): Tok[] {
  const toks: Tok[] = [];
  let cur = "";
  let has = false;
  const push = () => { if (has) toks.push({ t: "word", v: cur }); cur = ""; has = false; };
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === "\\") {
      if (text[i + 1] === "\n") { i++; continue; } // line continuation
      if (i + 1 < text.length) { cur += text[i + 1]; has = true; i++; }
      continue;
    }
    if (ch === "'") {
      const end = text.indexOf("'", i + 1);
      const stop = end === -1 ? text.length : end;
      cur += text.slice(i + 1, stop); has = true; i = stop;
      continue;
    }
    if (ch === '"') {
      let j = i + 1;
      for (; j < text.length && text[j] !== '"'; j++) {
        if (text[j] === "\\" && j + 1 < text.length && '"\\$`'.includes(text[j + 1])) j++;
        cur += text[j];
      }
      has = true; i = j;
      continue;
    }
    if (ch === "\n" || ch === ";") { push(); toks.push({ t: "op", v: ";" }); continue; }
    if (ch === "&" || ch === "|") {
      // `>&2`, `2>&1`, `&>file` are redirections, not separators
      if (ch === "&" && (text[i + 1] === ">" || (cur.endsWith(">") || cur.endsWith("<")))) { cur += ch; has = true; continue; }
      if (ch === "|" && cur.endsWith(">")) { cur += ch; continue; } // `>|` forces an overwrite
      push();
      if (text[i + 1] === ch || (ch === "|" && text[i + 1] === "&")) i++;
      toks.push({ t: "op", v: ";" });
      continue;
    }
    if (ch === "<" || ch === ">") {
      // a redirection starts a new word even with no space before it: `cat<file`, `echo x>>f`
      if (has && !/^(?:\d+|&|\d*[<>]+)$/.test(cur)) push();
      cur += ch; has = true;
      continue;
    }
    if (ch === "(" || ch === ")" || ch === "{" || ch === "}") {
      // grouping only when it stands alone; `{a,b}` and `$((1+2))` stay in the word
      if ((ch === "{" || ch === "}") && has) { cur += ch; continue; }
      if (ch === "{" && text[i + 1] !== " " && text[i + 1] !== "\n") { cur += ch; has = true; continue; }
      push(); toks.push({ t: "op", v: ";" });
      continue;
    }
    if (ch === " " || ch === "\t" || ch === "\r") { push(); continue; }
    if (ch === "#" && !has) { // comment to end of line
      const nl = text.indexOf("\n", i);
      i = nl === -1 ? text.length : nl - 1;
      continue;
    }
    cur += ch; has = true;
  }
  push();
  return toks;
}

/** Here-documents: the body is code only when it is fed to a shell. */
function liftHereDocs(text: string, bodies: string[]): string {
  if (!text.includes("<<")) return text;
  const lines = text.split("\n");
  const kept: string[] = [];
  const absent = new Set<string>();
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const m = /<<-?\s*(?:'([^']+)'|"([^"]+)"|\\?([A-Za-z_][A-Za-z0-9_]*))/.exec(line);
    if (!m || /<<</.test(line.slice(m.index, m.index + 3))) { kept.push(line); continue; }
    const tag = m[1] ?? m[2] ?? m[3];
    let j = i + 1;
    const body: string[] = [];
    if (absent.has(tag)) { kept.push(line); continue; }
    for (; j < lines.length && lines[j].trim() !== tag; j++) body.push(lines[j]);
    if (j >= lines.length) { absent.add(tag); kept.push(line); continue; } // never closed: not a body
    const head = line.slice(0, m.index) + " " + line.slice(m.index + m[0].length);
    kept.push(head);
    const feeder = tokenize(head).filter((t) => t.t === "word").map((t) => basename((t as { v: string }).v));
    if (feeder.some((w) => SHELLS.has(w))) bodies.push(body.join("\n"));
    i = j; // skip the body and its terminator
  }
  return kept.join("\n");
}

function build(words: string[]): SimpleCommand | null {
  const inputs: string[] = [];
  const outputs: string[] = [];
  const plain: string[] = [];
  for (let i = 0; i < words.length; i++) {
    const w = words[i];
    const m = /^(?:\d*|&)(>>|>\||>|<)(.*)$/.exec(w);
    if (m && !/^<<|^>\(|^<\(/.test(w.replace(/^\d+/, ""))) {
      let target = m[2];
      if (target === "" && i + 1 < words.length) target = words[++i];
      if (target && !target.startsWith("&")) (m[1] === "<" ? inputs : outputs).push(target);
      continue;
    }
    plain.push(w);
  }
  // leading VAR=value assignments
  let k = 0;
  while (k < plain.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(plain[k])) k++;
  // shell keywords and wrappers: `then sudo -u x env A=1 nohup timeout 5 curl …`
  for (let guard = 0; guard < 12 && k < plain.length; guard++) {
    if (KEYWORDS.has(plain[k])) { k++; while (k < plain.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(plain[k])) k++; continue; }
    const w = basename(plain[k]);
    if (!WRAPPERS.has(w)) break;
    const valued = WRAPPER_VALUE_OPTS[w] ?? new Set<string>();
    k++;
    while (k < plain.length) {
      const a = plain[k];
      if (a === "--") { k++; break; }
      if (a.startsWith("-")) { k += valued.has(a) ? 2 : 1; continue; }
      if (w === "env" && /^[A-Za-z_][A-Za-z0-9_]*=/.test(a)) { k++; continue; }
      if (w === "timeout" && /^\d+(?:\.\d+)?[smhd]?$/.test(a)) { k++; continue; }
      break;
    }
  }
  if (k >= plain.length) return inputs.length || outputs.length ? { verb: "", args: [], inputs, outputs } : null;
  return { verb: basename(plain[k]), args: plain.slice(k + 1), inputs, outputs };
}

function parseInto(text: string, depth: number, out: SimpleCommand[]): void {
  if (depth > MAX_DEPTH || out.length > 2000) return;
  const bodies: string[] = [];
  const flat = liftSubstitutions(liftHereDocs(text, bodies), bodies);
  let words: string[] = [];
  let dir: string | undefined;
  const flush = () => {
    if (words.length === 0) return;
    const cmd = build(words);
    words = [];
    if (!cmd) return;
    if (dir !== undefined) cmd.cwd = dir;
    out.push(cmd);
    // `cd X && …`: what follows runs in X. (A subshell's cd is taken to last too: the
    // error is on the side of looking in one more place.)
    if ((cmd.verb === "cd" || cmd.verb === "pushd") && cmd.args.length > 0) {
      const to = cmd.args.find((a) => !a.startsWith("-"));
      if (to && to !== "-") dir = /^(?:\/|~|\$\{?HOME)/.test(to) || dir === undefined ? to : `${dir}/${to}`;
    }
    // a shell given its program as text: bash -c "…", sh -lc '…'
    if (SHELLS.has(cmd.verb)) {
      const i = cmd.args.findIndex((a) => /^-[A-Za-z]*c$/.test(a));
      if (i !== -1 && cmd.args[i + 1]) parseInto(cmd.args[i + 1], depth + 1, out);
    }
    if (cmd.verb === "eval" && cmd.args.length) parseInto(cmd.args.join(" "), depth + 1, out);
  };
  for (const t of tokenize(flat)) {
    if (t.t === "op") flush();
    else words.push(t.v);
  }
  flush();
  for (const b of bodies) parseInto(b, depth + 1, out);
}

/** Every simple command in a command line, including the ones nested inside it. */
export function parseCommand(command: unknown): SimpleCommand[] {
  if (typeof command !== "string" || command.length === 0) return [];
  const out: SimpleCommand[] = [];
  try { parseInto(command.slice(0, MAX_COMMAND), 0, out); } catch { /* unreadable: nothing found, the text checks still run */ }
  return out;
}

/** The file an argument names, when the file is attached to something: `@f`, `if=f`, `--data=@f`. */
function fileIn(arg: string): string[] {
  const out = [arg];
  const eq = arg.indexOf("=");
  if (eq > 0 && eq < arg.length - 1) out.push(arg.slice(eq + 1));
  for (const s of [...out]) if (s.startsWith("@") && s.length > 1) out.push(s.slice(1));
  const colon = arg.lastIndexOf(":");
  if (colon > 0 && colon < arg.length - 1 && !arg.includes("://")) out.push(arg.slice(colon + 1)); // git show REV:path
  return out;
}

// ── which arguments are READ ────────────────────────────────────────────────

// Programs that touch a file without showing or copying what is in it.
const NO_CONTENT = new Set(["ls", "stat", "test", "[", "[[", "chmod", "chown", "chgrp", "touch", "file", "du", "realpath", "readlink", "basename", "dirname", "mkdir", "rm", "unlink", "shred", "cd", "pushd", "wc", "which", "type", "export", "unset", "true", "false", "echo", "printf", "alias", "for", "case", "select", "function", "in", "done", "fi", "esac", "popd", ":"]);
// Programs that take a private key as the key they log in with.
const KEY_USERS = new Set(["ssh", "scp", "sftp", "rsync", "git", "autossh", "mosh", "ansible", "ansible-playbook"]);
const KEY_TOOLS = new Set(["ssh-add", "ssh-keygen", "ssh-copy-id"]);
// Programs that load an env file into a process without printing it.
const ENV_LOADERS = new Set(["source", ".", "docker", "docker-compose", "podman", "podman-compose", "dotenv", "dotenvx", "env-cmd", "node", "bun", "deno", "npm", "npx", "pnpm", "yarn", "uvicorn", "flask", "direnv"]);
const GIT_QUIET = new Set(["add", "rm", "mv", "check-ignore", "status", "ls-files", "update-index", "restore", "checkout", "stash", "commit"]);
const COPIERS = new Set(["cp", "mv", "install", "ln"]);
// Programs whose first plain argument is a pattern or a script, not a file:
// `grep "secrets/x.json" notes.md` searches FOR that text, it does not open that file.
const PATTERN_FIRST = new Set(["grep", "egrep", "fgrep", "rg", "ag", "ack", "sed", "awk", "gawk", "mawk", "jq", "yq", "pgrep", "pkill"]);

/**
 * The arguments of each command that the command would read the CONTENT of. `isSecret` says
 * which paths matter; an argument is reported only when the program is not one that merely
 * uses or names the file (ssh -i key, source .env, chmod, cp … into it).
 */
export function contentReads(cmds: SimpleCommand[], isSecret: (arg: string, cwd?: string) => "key" | "env" | "other" | null): Array<{ verb: string; path: string }> {
  const hits: Array<{ verb: string; path: string }> = [];
  for (const c of cmds) {
    for (const p of c.inputs) for (const f of fileIn(p)) if (isSecret(f, c.cwd)) hits.push({ verb: c.verb || "<", path: f });
    if (!c.verb || NO_CONTENT.has(c.verb)) continue;
    // where the pattern is: the first plain argument, unless it was given with -e / -f
    const patternAt = PATTERN_FIRST.has(c.verb) && !c.args.some((x) => x === "-e" || x === "-f" || x.startsWith("--regexp") || x.startsWith("--file"))
      ? c.args.findIndex((x) => !x.startsWith("-"))
      : -1;
    for (let i = 0; i < c.args.length; i++) {
      if (i === patternAt) continue;
      const a = c.args[i];
      for (const f of fileIn(a)) {
        const kind = isSecret(f, c.cwd);
        if (!kind) continue;
        const prev = c.args[i - 1] ?? "";
        if (kind === "key") {
          if (KEY_TOOLS.has(c.verb)) continue;
          if (KEY_USERS.has(c.verb) && (prev === "-i" || a.startsWith("-i") || /identityfile/i.test(a) || /identityfile/i.test(prev))) continue;
        }
        if (kind === "env") {
          if (c.verb === "source" || c.verb === ".") continue;
          if (ENV_LOADERS.has(c.verb) && (/^--?env[-_]?file/i.test(a) || /^--?env[-_]?file$/i.test(prev) || prev === "-e" || prev === "-f")) continue;
        }
        if (c.verb === "git" && GIT_QUIET.has(c.args.find((x) => !x.startsWith("-")) ?? "")) continue;
        // the last argument of a copy is where it writes, not what it reads
        if (COPIERS.has(c.verb) && i === c.args.length - 1 && c.args.filter((x) => !x.startsWith("-")).length > 1) continue;
        hits.push({ verb: c.verb, path: f });
      }
    }
  }
  return hits;
}

// ── which files are WRITTEN ─────────────────────────────────────────────────

/**
 * Files each command writes or replaces ("write"), or removes or changes the permissions
 * of ("meta") — as far as the text shows. A caller may care about "meta" for some files
 * only: `chmod 600 ~/.ssh/authorized_keys` is ordinary, removing a guard's rules is not.
 */
export interface WriteTarget { verb: string; path: string; kind: "write" | "meta"; cwd?: string }
export function writeTargets(cmds: SimpleCommand[]): WriteTarget[] {
  const all: WriteTarget[] = [];
  for (const c of cmds) {
    const hits: WriteTarget[] = [];
    for (const p of c.outputs) hits.push({ verb: c.verb || ">", path: p, kind: "write" });
    const files = c.args.filter((a) => !a.startsWith("-"));
    switch (c.verb) {
      case "tee": case "truncate":
        for (const f of files) hits.push({ verb: c.verb, path: f, kind: "write" });
        break;
      case "rm": case "unlink": case "shred": case "rmdir":
        for (const f of files) hits.push({ verb: c.verb, path: f, kind: "meta" });
        break;
      case "cp": case "mv": case "install": case "ln": case "rsync": case "scp":
        if (files.length > 1) hits.push({ verb: c.verb, path: files[files.length - 1], kind: "write" });
        if (c.verb === "mv") for (const f of files.slice(0, -1)) hits.push({ verb: c.verb, path: f, kind: "meta" }); // the source is removed
        break;
      case "sed": case "perl": case "ruby": case "gawk":
        if (c.args.some((a) => /^-[A-Za-z]*i/.test(a) || a === "--in-place" || a.startsWith("--in-place=") || a === "inplace"))
          for (const f of files.slice(1)) hits.push({ verb: c.verb, path: f, kind: "write" });
        break;
      case "dd":
        for (const a of c.args) if (a.startsWith("of=")) hits.push({ verb: "dd", path: a.slice(3), kind: "write" });
        break;
      case "curl": case "wget":
        for (let i = 0; i < c.args.length; i++) {
          const a = c.args[i];
          if ((a === "-o" || a === "-O" || a === "--output" || a === "--output-document") && c.args[i + 1] && !(c.verb === "curl" && a === "-O")) hits.push({ verb: c.verb, path: c.args[i + 1], kind: "write" });
          const m = /^--output(?:-document)?=(.+)$/.exec(a);
          if (m) hits.push({ verb: c.verb, path: m[1], kind: "write" });
        }
        break;
      case "chmod": case "chown": case "chattr":
        // changing who may write the guard's own files is a write to them
        for (const f of files.slice(1)) hits.push({ verb: c.verb, path: f, kind: "meta" });
        break;
    }
    for (const h of hits) all.push(c.cwd === undefined ? h : { ...h, cwd: c.cwd });
  }
  return all;
}

/** A crontab invocation that installs or edits a table (anything but listing it). */
export function installsCrontab(cmds: SimpleCommand[]): boolean {
  return cmds.some((c) => c.verb === "crontab" && !(c.args.includes("-l") && !c.args.includes("-e") && !c.args.includes("-r")));
}

// ── network programs ────────────────────────────────────────────────────────

/**
 * Which of the listed network tools a command runs. A plain entry ("curl", "openssl
 * s_client") is matched against the program that runs and its first arguments; an entry
 * with ".*" is a pattern over one simple command's own text.
 */
export function networkTool(cmds: SimpleCommand[], listed: readonly string[]): string | null {
  for (const entry of listed) {
    if (typeof entry !== "string" || entry.length === 0) continue;
    if (entry.includes(".*")) {
      let re: RegExp;
      // `.*` bounded, so a long command cannot make the pattern backtrack for seconds
      try { re = new RegExp(entry.replace(/\.\*/g, "[^\\n]{0,2000}"), "i"); } catch { continue; }
      for (const c of cmds) if (c.verb && re.test(`${c.verb} ${c.args.join(" ")}`.slice(0, 8000))) return entry;
      continue;
    }
    const parts = entry.trim().split(/\s+/);
    for (const c of cmds) {
      if (c.verb !== parts[0]) continue;
      if (parts.slice(1).every((p, i) => c.args[i] === p)) return entry;
    }
  }
  return null;
}
