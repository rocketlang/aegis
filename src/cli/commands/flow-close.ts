// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// aegis flow-close — Claude Code Stop hook (governed-turn-protocol §19, P5).
//
// At the end of every turn: grade the agent's last message with show-me-the-receipts (from the session
// record; no command is run), judge it against the flow's mandate (required_return_proof), and write a
// signed flow receipt (<aegis dir>/flow-receipts/, owner-only).
//
// @rule:GTP-025 a flow whose required proof is missing does not close as done. When the box enforces
// mandates (enforcement.mode and kavach.mandate both "enforce"), the agent is sent back once to prove or
// correct its claim; the second time it is let go and the receipt stays "open". Otherwise it is recorded.
// Never traps the agent: any fault exits 0.

import { readFileSync } from "fs";
import { loadConfig } from "../../core/config";
import { mandateEnforced } from "../../kavach/mandate";
import { closeFlow } from "../../kavach/flow-close";

export default async function flowClose(): Promise<void> {
  let input: Record<string, unknown> = {};
  try { input = JSON.parse(readFileSync(0, "utf8") || "{}"); } catch { process.exit(0); } // fd 0: stdin may be a socket
  const { receipt, reason } = closeFlow(input);
  if (!receipt) {
    if (reason) process.stderr.write(`[flow-close] ${reason}\n`);
    process.exit(0);
  }
  if (receipt.status === "closed" || !receipt.proof) process.exit(0);

  const lines = receipt.proof.missing.map((m) => `- ${m}`);
  let enforced = false;
  try { enforced = mandateEnforced(loadConfig()); } catch { /* the defaults: record only */ }
  // @rule:GTP-025 a flow whose mandate requires proof does not close on an unproven claim
  if (enforced && input.stop_hook_active !== true) {
    const reason = [
      `🧾 GTP-025: this flow's mandate (${receipt.mandate?.mandate_id}) requires "${receipt.proof.required}" before it closes, and your last message does not meet it:`,
      ...lines,
      "",
      "Before you finish, prove each claim (run the check now and let the output show it) or correct your message to say what is actually true.",
    ].join("\n");
    process.stdout.write(JSON.stringify({ decision: "block", reason }));
    process.exit(0);
  }
  process.stderr.write(`[flow-close] flow left open (GTP-025, ${receipt.proof.required}${enforced ? ", after one retry" : ", recorded only"}):\n${lines.join("\n")}\n`);
  process.exit(0);
}
