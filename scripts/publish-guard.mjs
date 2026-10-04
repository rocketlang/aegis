#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-only
//
// publish-guard — refuses `npm publish` anywhere but a release workflow on a tag.
// Run first in `prepublishOnly` by the root package and by the packages under packages/
// (as ../../scripts/publish-guard.mjs). packages/kavachos keeps its own copy.
//
// WHY: a release that can be checked comes from a clean checkout of a tag, published by
// CI with provenance. Earlier versions of these packages were published from a machine,
// and the registry holds nothing that says which commit they came from. This turns the
// rule into a refusal instead of a habit.
//
// Allowed: a release workflow on a tag (GITHUB_ACTIONS + GITHUB_REF_TYPE=tag), and a
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
const pkg = env.npm_package_name || 'this package';

if (dryRun) {
  console.error('publish-guard: dry run — allowed, nothing is published');
  process.exit(0);
}
if (inWorkflow && onTag) {
  console.error(`publish-guard: release workflow on tag ${env.GITHUB_REF_NAME} — allowed`);
  process.exit(0);
}
console.error(
  `publish-guard: REFUSED. ${pkg} is published only by its release workflow, from a tag.\n` +
  (inWorkflow
    ? `  This run is on a ${env.GITHUB_REF_TYPE || 'branch'}, not a tag.\n`
    : '  This is not the release workflow.\n') +
  '  To release: push the tag named in the workflow file for this package.\n' +
  '  To rehearse: npm publish --dry-run'
);
process.exit(1);
