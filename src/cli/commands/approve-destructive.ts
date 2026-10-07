// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// aegis approve-destructive [code]
//
// A PERSON runs this, in their own terminal, after the destructive gate has refused a
// command they do want run. With no code it lists what is waiting. With a code it approves
// that one command, once, for ten minutes.
//
// @rule:KAV-098 — the shield stops this command when it arrives as a tool call: an agent
// approving its own refused command is the thing this exists to prevent.

import { APPROVAL_TTL_MS } from "../../kavach/destructive-approval";
import {
  approvePendingAuthority, listPendingAuthority, authorityMode, authorityHint,
} from "../../kavach/approval-authority";
import { recordRefusal } from "../../core/refusal-ledger";

export default async function approveDestructive(args: string[]): Promise<void> {
  const code = (args[0] ?? "").trim().toLowerCase();
  const mode = authorityMode();

  // Separation is the default: with no approver configured, there is nothing to approve WITH,
  // and that is deliberate — an agent must not be able to approve its own command.
  if (mode === "none") {
    process.stderr.write(authorityHint());
    process.exit(1);
  }
  if (mode === "insecure-local") {
    process.stderr.write(
      "[KAVACH] Insecure single-box mode: this approval lives in a file your agent's own uid can " +
      "write. Set up the separate-uid approver (`aegis init`) for a real boundary.\n",
    );
  }

  if (!code) {
    const pending = await listPendingAuthority();
    if (pending.length === 0) {
      console.log("Nothing is waiting for approval.");
      process.exit(0);
    }
    console.log("Refused commands waiting for a person's approval:\n");
    for (const p of pending) {
      const mins = Math.max(0, Math.round((Date.now() - p.at) / 60000));
      console.log(`  ${p.code}   ${mins} min ago   ${p.rule}`);
      console.log(`             ${p.shown}`);
    }
    console.log("\nTo approve one, once:  aegis approve-destructive <code>");
    process.exit(0);
  }

  const done = await approvePendingAuthority(code);
  if (!done) {
    console.error(`No refused command is waiting under the code '${code}'. It may have expired (30 minutes) or been approved already.`);
    console.error("Run `aegis approve-destructive` with no code to see what is waiting.");
    process.exit(1);
  }
  recordRefusal({ gate: "aegis-destructive", kind: "override", rule: "KAV-098" });
  console.log(`Approved, once, for ${Math.round(APPROVAL_TTL_MS / 60000)} minutes:`);
  console.log(`  ${done.shown}`);
  console.log(`  (matched: ${done.rule})`);
  console.log("The same command, run again unchanged, will now go through one time.");
  process.exit(0);
}
