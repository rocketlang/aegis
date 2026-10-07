// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.

// aegis approver-daemon — run the separate-uid approver (KAV-098 hardened mode).
//
// It MUST run as a dedicated account (e.g. `aegis-approver`), NOT as the account the agent
// runs as — that separation is the whole point. It owns the approval store and listens on two
// unix sockets; see src/kavach/approver-daemon.ts.
//
//   --store <dir>          store directory this daemon owns (default: $AEGIS_APPROVER_STORE
//                          or ~/.aegis-approver). Must be writable only by this account.
//   --consume <path>       consume socket (agents may ask). Default $AEGIS_APPROVER_CONSUME_SOCKET.
//   --approve <path>       approve socket (people only).     Default $AEGIS_APPROVER_APPROVE_SOCKET.
//
// The agent processes are then pointed at the SAME socket paths via those env vars, which flips
// the gate into hardened mode.

import { homedir } from "os";
import { join } from "path";
import { startApproverDaemon } from "../../kavach/approver-daemon";

function flag(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  return i >= 0 && i + 1 < args.length ? args[i + 1] : undefined;
}

export default async function approverDaemon(args: string[]): Promise<void> {
  const store = flag(args, "--store") || process.env.AEGIS_APPROVER_STORE || join(homedir(), ".aegis-approver");
  const consumeSocketPath =
    flag(args, "--consume") || process.env.AEGIS_APPROVER_CONSUME_SOCKET || join(store, "consume.sock");
  const approveSocketPath =
    flag(args, "--approve") || process.env.AEGIS_APPROVER_APPROVE_SOCKET || join(store, "approve.sock");

  // A warning, not a refusal: enforcement of "different uid" is the OS's job (file ownership on
  // the store and socket perms). We say it loudly so a misconfiguration is visible.
  const warnSameUser = !process.env.AEGIS_APPROVER_SUPPRESS_UID_WARN;

  const { stop } = startApproverDaemon({ storeDir: store, consumeSocketPath, approveSocketPath });
  if (warnSameUser) {
    process.stderr.write(
      "[aegis-approver] Running. This daemon MUST run as a dedicated account the agent cannot use. " +
      "Confirm the store dir and approve socket are owned by this account and unreadable to the agent's uid.\n",
    );
  }

  const shutdown = () => { stop(); process.exit(0); };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
  // Stay alive.
  await new Promise<void>(() => { /* until a signal */ });
}
