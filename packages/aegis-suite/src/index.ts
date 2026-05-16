// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// @rocketlang/aegis-suite — meta-package. The value of this package is its
// dependency list (installs all 6 OSS @rocketlang governance primitives in
// one shot). Import from the sub-packages by name:
//
//   import { runProbe } from '@rocketlang/lakshmanrekha';
//   import { trust, scan } from '@rocketlang/chitta-detect';
//   import { verifyMudrika, scoreAxis } from '@rocketlang/hanumang-mandate';
//   import { verifyApprovalToken } from '@rocketlang/aegis-guard';
//
// The `aegis` and `kavachos` CLIs ship as bin entries in those packages.
// See README for the unified workflow.

export const AEGIS_SUITE_VERSION = '0.1.0';
export const AEGIS_SUITE_BUNDLED_PACKAGES = [
  '@rocketlang/aegis',
  '@rocketlang/kavachos',
  '@rocketlang/aegis-guard',
  '@rocketlang/chitta-detect',
  '@rocketlang/lakshmanrekha',
  '@rocketlang/hanumang-mandate',
] as const;

export interface SuiteManifest {
  version: typeof AEGIS_SUITE_VERSION;
  bundled_packages: typeof AEGIS_SUITE_BUNDLED_PACKAGES;
  excluded: { package: string; reason: string }[];
}

export const SUITE_MANIFEST: SuiteManifest = {
  version: AEGIS_SUITE_VERSION,
  bundled_packages: AEGIS_SUITE_BUNDLED_PACKAGES,
  excluded: [
    { package: '@rocketlang/n8n-nodes-kavachos', reason: 'n8n-specific integration — install separately if using n8n' },
    { package: '@rocketlang/kavachos-ee', reason: 'BSL-1.1 EE, not on npm — contact captain@ankr.in' },
  ],
};
