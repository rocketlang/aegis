#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-only
//
// publish-guard — refuses `npm publish` of @xshieldai/aegis anywhere but the release
// workflow. Same guard as packages/kavachos/scripts/publish-guard.mjs; kept as a second
// copy so each package's release depends on nothing outside what it names.
//
// WHY: a release that can be checked comes from a clean checkout of a tag, published by
// CI with provenance. Every earlier version of this package was published from a machine,
// and the registry holds nothing that says which commit it came from. This turns the
// rule into a refusal instead of a habit.
//
// Allowed: the release workflow on a tag (GITHUB_ACTIONS + GITHUB_REF_TYPE=tag), and a
// dry run anywhere (npm sets npm_config_dry_run). Everything else exits 1.
//
// WHERE TRUST NOW SITS: `npm publish --ignore-scripts` skips this file, and the two
// variables it reads can be set by hand. This stops a mistake, not a determined person.
// What catches the rest is outside this repository: a version published that way carries
// no provenance, and a provenance check on the published package fails.

const env = process.env;
const dryRun = env.npm_config_dry_run === 'true';
const inWorkflow = env.GITHUB_ACTIONS === 'true';
const onTag = env.GITHUB_REF_TYPE === 'tag';

if (dryRun) {
  console.error('publish-guard: dry run — allowed, nothing is published');
  process.exit(0);
}
if (inWorkflow && onTag) {
  console.error(`publish-guard: release workflow on tag ${env.GITHUB_REF_NAME} — allowed`);
  process.exit(0);
}
console.error(
  'publish-guard: REFUSED. This package is published only by the release workflow, from a tag.\n' +
  (inWorkflow
    ? `  This run is on a ${env.GITHUB_REF_TYPE || 'branch'}, not a tag.\n`
    : '  This is not the release workflow.\n') +
  '  To release: git tag v<version> && git push origin v<version>\n' +
  '  To rehearse: npm publish --dry-run'
);
process.exit(1);
