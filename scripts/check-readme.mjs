#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-only
//
// check-readme — refuses a release whose README does not describe the package it ships in.
//
//   node scripts/check-readme.mjs <package-dir>
//
// WHY: six packages were released with READMEs titled for, and telling the reader to
// install, a different package name. The README travels inside the tarball and is what the
// registry page shows, so a stale one sends readers to the wrong package. Three checks:
//
//   1. the first heading names this package
//   2. no install line or import names a package under a retired scope
//   3. every relative link points at a file that is in the tarball
//
// Exit: 0 all three hold · 1 one does not · 2 refused to start · 3 this script broke.
// It packs the package to a temporary directory to get the file list, so run it after any build.

import { readFileSync, existsSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const RETIRED = /@(rocketlang|ankr)\/[\w.-]+/g;
// Named on purpose in a README as something that is NOT on npm.
const ALLOWED = new Set(['@rocketlang/kavachos-ee']);

function main() {
  const dir = process.argv[2];
  if (!dir || !existsSync(join(dir, 'package.json')) || !existsSync(join(dir, 'README.md'))) {
    console.error('check-readme: REFUSED — give a directory that holds package.json and README.md');
    return 2;
  }
  const pkg = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
  const readme = readFileSync(join(dir, 'README.md'), 'utf8');
  // The file list is read from a real packed tarball with tar, not from `npm pack --json`:
  // the shape of that JSON differs between npm versions (npm 12 on the release runner did
  // not return the array npm 10 and 11 do, and the first rehearsal of this check broke).
  const tmp = mkdtempSync(join(tmpdir(), 'check-readme-'));
  let files;
  try {
    execFileSync('npm', ['pack', '--ignore-scripts', '--pack-destination', tmp], { cwd: dir, stdio: 'ignore' });
    const tgz = readdirSync(tmp).filter((f) => f.endsWith('.tgz'));
    if (tgz.length !== 1) throw new Error(`expected one tarball from npm pack, found ${tgz.length}`);
    const listing = execFileSync('tar', ['-tzf', join(tmp, tgz[0])], { encoding: 'utf8' });
    files = new Set(listing.split('\n').filter((l) => l.startsWith('package/') && !l.endsWith('/')).map((l) => l.slice('package/'.length)));
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
  if (!files.has('package.json') || !files.has('README.md')) throw new Error('the packed tarball has no package.json or README.md');
  const fails = [];

  const title = (readme.match(/^#\s+(.+)$/m) || [])[1] || '';
  if (!title.includes(pkg.name)) fails.push(`the first heading is "${title}", which does not name ${pkg.name}`);

  const retired = [...new Set(readme.match(RETIRED) || [])].filter((n) => !ALLOWED.has(n));
  if (retired.length) fails.push(`it names packages under a retired scope: ${retired.join(', ')}`);

  const missing = [];
  for (const m of readme.matchAll(/\]\(([^)\s]+)\)/g)) {
    const target = m[1].split('#')[0];
    if (!target || /^[a-z][a-z0-9+.-]*:/i.test(target)) continue; // anchors and absolute URLs
    const norm = target.replace(/^\.\//, '');
    if (norm.startsWith('../') || !files.has(norm)) missing.push(target);
  }
  if (missing.length) fails.push(`it links to files that are not in the tarball: ${[...new Set(missing)].join(', ')}`);

  if (fails.length) {
    console.error(`check-readme: REFUSED for ${pkg.name} — the README does not describe the package it ships in:`);
    for (const f of fails) console.error('  - ' + f);
    return 1;
  }
  console.error(`check-readme: ${pkg.name} — heading, package names and ${files.size} shipped files agree with the README`);
  return 0;
}

try {
  process.exit(main());
} catch (e) {
  console.error('check-readme: BROKE — this is not a result about the README:', e && e.message);
  process.exit(3);
}
