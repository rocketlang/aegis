// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// @xshieldai/aegis-suite — meta-package. The value of this package is its
// dependency list (installs all 6 OSS @rocketlang governance primitives in
// one shot). Import from the sub-packages by name:
//
//   import { runProbe } from '@xshieldai/lakshmanrekha';
//   import { trust, scan } from '@xshieldai/chitta-detect';
//   import { verifyMudrika, scoreAxis } from '@xshieldai/hanumang-mandate';
//   import { verifyApprovalToken } from '@xshieldai/aegis-guard';
//
// The `aegis` and `kavachos` CLIs ship as bin entries in those packages.
// See README for the unified workflow.

export const AEGIS_SUITE_VERSION = '0.2.5';
export const AEGIS_SUITE_BUNDLED_PACKAGES = [
  '@xshieldai/aegis',
  '@xshieldai/agent-kernel',
  '@xshieldai/aegis-guard',
  '@xshieldai/chitta-detect',
  '@xshieldai/lakshmanrekha',
  '@xshieldai/hanumang-mandate',
] as const;

export interface SuiteManifest {
  version: typeof AEGIS_SUITE_VERSION;
  bundled_packages: typeof AEGIS_SUITE_BUNDLED_PACKAGES;
  excluded: { package: string; reason: string }[];
}

// @rule:ACC-003 — wireAllToBus helper (v0.2.0+)
export { wireAllToBus, unwireAll, getWiredHandle } from './wire.js';
export type { EventBus, AccReceipt, WireHandle, WireAllOpts } from './wire.js';

export const SUITE_MANIFEST: SuiteManifest = {
  version: AEGIS_SUITE_VERSION,
  bundled_packages: AEGIS_SUITE_BUNDLED_PACKAGES,
  excluded: [
    { package: '@xshieldai/n8n-nodes', reason: 'n8n-specific integration — install separately if using n8n' },
    { package: '@rocketlang/kavachos-ee', reason: 'BSL-1.1 EE, not on npm — contact captain@ankr.in' },
  ],
};
