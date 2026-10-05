// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// AEGIS Shield — path rules.
//
// @rule:KAV-094 a path rule is matched against the path the tool would really open: `~` and
//               relative paths resolved, `/./` and `/../` collapsed, symlinks followed where
//               the file exists — and on whole path segments, never on a substring.
//
// Two kinds of rule, both written as before so existing shield-rules.json files stay valid:
//   "/etc/cron.d/"   ends with "/"  → that directory and everything under it
//   "/.bashrc"       anything else  → those segments, ending at the end of the path or at "/"
// So "/.bashrc" matches /home/u/.bashrc and not /home/u/docs/.bashrc-explained.md, and
// "/.profile" does not match a folder named .profiles.
//
// CEILING (state it, never round up): a rule sees a path. It cannot see a hard link, a file
// reached through a variable or a script, a bind mount, or a path the tool builds later.

import { resolve, basename } from "path";
import { realpathSync, statSync } from "fs";

export interface PathContext {
  /** Working directory of the tool call; relative paths are resolved against it. */
  cwd?: string;
  /** Home directory `~` stands for. */
  home?: string;
}

const homeOf = (ctx?: PathContext): string => ctx?.home || process.env.HOME || "/root";

/**
 * The paths a tool given `raw` could open: the lexical path, and the path after symlinks
 * when it (or its directory) exists. Empty for input that is not a usable path.
 */
export function candidatePaths(raw: unknown, ctx?: PathContext): string[] {
  if (typeof raw !== "string") return [];
  let p = raw.trim();
  if (p.length === 0 || p.length > 4096 || p.includes("\0")) return [];
  if ((p.startsWith('"') && p.endsWith('"')) || (p.startsWith("'") && p.endsWith("'"))) p = p.slice(1, -1);
  const home = homeOf(ctx);
  if (p === "~") p = home;
  else if (p.startsWith("~/")) p = home + p.slice(1);
  p = p.replace(/^\$\{?HOME\}?(?=\/|$)/, home);
  const lexical = resolve(ctx?.cwd || process.cwd(), p);
  const out = [lexical];
  try {
    const real = realpathSync(lexical);
    if (real !== lexical) out.push(real);
  } catch {
    // the file does not exist yet (a Write): follow the directory, keep the name
    try {
      const dir = realpathSync(resolve(lexical, ".."));
      const viaDir = resolve(dir, basename(lexical));
      if (viaDir !== lexical) out.push(viaDir);
    } catch { /* neither exists — the lexical path is all there is */ }
  }
  return out;
}

/** Does `path` (already resolved) fall under `rule`? Whole segments only. */
export function matchPathRule(path: string, rule: string): boolean {
  if (typeof rule !== "string" || rule.length < 2 || !rule.startsWith("/")) {
    // a rule without a leading slash is a bare name: match it as one whole segment
    if (typeof rule !== "string" || rule.length === 0) return false;
    rule = "/" + rule;
  }
  if (rule.endsWith("/")) return path.includes(rule) || (path + "/").endsWith(rule);
  for (let i = path.indexOf(rule); i !== -1; i = path.indexOf(rule, i + 1)) {
    const next = path[i + rule.length];
    if (next === undefined || next === "/") return true;
  }
  return false;
}

export function firstMatchingRule(path: string, rules: readonly string[]): string | null {
  for (const r of rules) if (matchPathRule(path, r)) return r;
  return null;
}

// Files that hold secrets wherever they live, matched on the file's own name. These are
// built in: a rules file adds to them and cannot switch them off by emptying a list.
const CREDENTIAL_NAMES: ReadonlyArray<{ id: string; re: RegExp }> = [
  // .env and its variants; the committed templates (.env.example and friends) are not secrets
  { id: ".env", re: /^\.env(?:\.(?!(?:example|sample|template|tpl|dist|defaults?|schema)$)[A-Za-z0-9_.-]+)?$/ },
  { id: "ssh private key", re: /^id_(?:rsa|dsa|ecdsa|ed25519)(?:_[A-Za-z0-9-]+)?$/ },
  { id: "credentials file", re: /^(?:credentials|secrets?)\.(?:json|ya?ml|toml|ini|env|txt|properties|xml|csv)$/ },
  { id: "dot credential file", re: /^\.(?:netrc|git-credentials|pgpass|npmrc|pypirc)$/ },
  { id: "service account key", re: /^service-account[\w-]*\.json$/ },
];

/** The built-in credential kind this file name belongs to, or null. */
export function credentialName(path: string): string | null {
  const name = basename(path);
  for (const c of CREDENTIAL_NAMES) if (c.re.test(name)) return c.id;
  // The bare names `credentials` and `secrets` are a secrets FILE in a tool's own dot
  // directory (~/.aws/credentials, ~/.config/x/credentials) and a source FOLDER in a
  // project (src/credentials/). A folder is not a secret; a file by that name is.
  if (/^(?:credentials|secrets?)$/.test(name)) {
    if (/\/\.[^/]+\/[^/]*$/.test(path)) return "credentials file";
    try { if (statSync(path).isFile()) return "credentials file"; } catch { /* not there: a name alone decides nothing */ }
  }
  // A folder named secrets/ or credentials/ holds data files that are secrets
  // (secrets/api-keys.json) and, in a source tree, code and docs that are not
  // (src/credentials/Api.credentials.ts, secrets/README.md). The file's kind decides.
  if (/\/(?:secrets?|credentials)\/(?:[^/]+\/)*[^/]+$/.test(path) && !SOURCE_OR_DOC.test(name)) return "file in a secrets folder";
  return null;
}

// Code and documentation: kinds of file that describe secrets rather than hold them.
const SOURCE_OR_DOC = /\.(?:md|mdx|rst|adoc|html?|css|ts|tsx|js|jsx|mjs|cjs|py|rb|go|rs|java|kt|cs|php|c|h|cpp|hpp|swift|sh|sql|proto|graphql|vue|svelte|lock|d\.ts|example|sample|template|tpl)$/i;

// Directories whose contents are keys, whatever the files are called. The few files in
// them that are public by nature are named here and left alone.
const SECRET_DIRS: ReadonlyArray<{ dir: string; publicNames: RegExp }> = [
  { dir: "/.ssh", publicNames: /^(?:.+\.pub|known_hosts(?:\.old)?|config|authorized_keys|environment|rc)$/ },
  { dir: "/.gnupg", publicNames: /^(?:pubring\.kbx~?|trustdb\.gpg|gpg\.conf|gpg-agent\.conf|dirmngr\.conf|.+\.pub)$/ },
  { dir: "/.aws", publicNames: /^(?:config|cli)$/ },
];

/**
 * The secret directory `path` is, or is inside of, when the file is not one of that
 * directory's public files. `~/.ssh/deploy_key`, `~/.ssh` itself and `~/.ssh/*` are hits;
 * `~/.ssh/id_rsa.pub` and `~/.ssh/known_hosts` are not.
 */
export function secretDir(path: string): string | null {
  for (const s of SECRET_DIRS) {
    if (path.endsWith(s.dir)) return s.dir;
    const i = path.indexOf(s.dir + "/");
    if (i === -1) continue;
    const rest = path.slice(i + s.dir.length + 1);
    if (rest.length === 0) return s.dir;
    if (!s.publicNames.test(basename(rest)) || rest.includes("/")) return s.dir;
  }
  return null;
}
