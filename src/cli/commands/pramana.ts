// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// aegis pramana file <abs-path> [expected-sha256]
// aegis pramana port <port> [host]
// aegis pramana commit <repo-dir> [path ...]
//
// The sounding pipe. Every check here reaches reality by a route the actuator did not use.
// @rule:PRA-001 @rule:PRA-003

import { confirmFileWrite, confirmServiceListening, confirmCommit, renderConfirmation } from "../../kavach/pramana";

export default async function pramanaCmd(args: string[]): Promise<void> {
  const kind = args[0];

  if (kind === "file") {
    const path = args[1];
    if (!path) {
      console.error("usage: aegis pramana file <abs-path> [expected-sha256]");
      process.exit(1);
    }
    const c = confirmFileWrite(path, args[2]);
    process.stdout.write(renderConfirmation(c));
    process.exit(c.state === "confirmed" ? 0 : 2);
  }

  if (kind === "port") {
    const port = Number(args[1]);
    if (!port) {
      console.error("usage: aegis pramana port <port> [host]");
      process.exit(1);
    }
    const c = await confirmServiceListening(port, args[2] || "127.0.0.1");
    process.stdout.write(renderConfirmation(c));
    process.exit(c.state === "confirmed" ? 0 : 2);
  }

  if (kind === "commit") {
    const dir = args[1];
    if (!dir) {
      console.error("usage: aegis pramana commit <repo-dir> [expected-path ...]");
      process.exit(1);
    }
    const c = confirmCommit(dir, args.slice(2));
    process.stdout.write(renderConfirmation(c));
    process.exit(c.state === "confirmed" ? 0 : 2);
  }

  console.error("usage: aegis pramana <file|port|commit> ...");
  process.exit(1);
}
