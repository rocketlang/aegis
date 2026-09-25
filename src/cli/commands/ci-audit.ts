// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// `aegis ci-audit [--dir <repo>] [--json]` — AF-T-710. Exit 1 on any undeclared publish
// step; egress reported, third-party actions a scoped null. See src/kavach/ci-audit.ts.

import { auditWorkflowsDir, readCiDeclarations, renderCiAudit } from "../../kavach/ci-audit";

export default async function ciAudit(args: string[]): Promise<void> {
  const di = args.indexOf("--dir");
  const dir = di >= 0 && args[di + 1] ? args[di + 1] : process.cwd();
  const report = auditWorkflowsDir(dir, readCiDeclarations(dir));

  if (args.includes("--json")) process.stdout.write(JSON.stringify(report, null, 2) + "\n");
  else process.stdout.write(renderCiAudit(report));

  process.exit(report.undeclaredPublishes > 0 ? 1 : 0);
}
