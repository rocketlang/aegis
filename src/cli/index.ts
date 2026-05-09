#!/usr/bin/env bun
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.
// AEGIS CLI — aegis status | kill | pause | resume [agent-id] | budget | check-budget | check-spawn | check-destructive | check-shield | register | close | quarantine | valve | init | bg

const command = Bun.argv[2] || "status";
const args = Bun.argv.slice(3);

async function main() {
  switch (command) {
    case "status":
      return (await import("./commands/status")).default(args);
    case "kill":
      return (await import("./commands/kill")).default(args);
    case "pause":
      return (await import("./commands/pause")).default(args, "pause");
    case "resume":
      // If an agent-id arg is given → show resume manifest (V2-050)
      // If no args → SIGCONT all paused processes
      if (args.length > 0 && !args[0].startsWith("--")) {
        return (await import("./commands/resume")).default(args);
      }
      return (await import("./commands/pause")).default(args, "resume");
    case "budget":
      return (await import("./commands/budget")).default(args);
    case "check-budget":
      return (await import("./commands/check-budget")).default(args);
    case "check-spawn":
      return (await import("./commands/check-spawn")).default(args);
    case "check-destructive":
      return (await import("./commands/check-destructive")).default(args);
    case "check-shield":
      return (await import("./commands/check-shield")).default(args);
    case "check-chitta":
      return (await import("./commands/check-chitta")).default(args);
    case "register":
      return (await import("./commands/register")).default(args);
    case "close":
      return (await import("./commands/close")).default(args);
    case "quarantine":
      return (await import("./commands/quarantine")).default(args);
    case "valve":
      return (await import("./commands/valve")).default(args);
    case "cost":
      return (await import("./commands/cost")).default(args);
    case "init":
      return await (await import("./commands/init")).default(args);
    case "statusline":
      return (await import("./commands/statusline")).default(args);
    case "bg":
      return (await import("./commands/bg")).default(args);
    case "help":
    case "--help":
    case "-h":
      printHelp();
      break;
    default:
      console.error(`Unknown command: ${command}`);
      printHelp();
      process.exit(1);
  }
}

function printHelp() {
  console.log(`
AEGIS — The kill-switch between your AI agents and your credit card

Usage: aegis <command> [options]

Commands:
  status          Show current spend, budget, active sessions
  kill            Kill all claude/agent processes (SIGKILL)
  kill --stop     Pause all processes (SIGSTOP, resumable)
  kill --session  Kill specific session
  pause               Pause all agent processes (SIGSTOP)
  resume              Resume paused processes (SIGCONT)
  resume <agent-id>   Show resume manifest for a force-closed agent (V2-050)
  budget show     Show budget limits
  budget set      Set budget (e.g. aegis budget set daily 50)
  check-budget    Hook: check budget before tool use (exit 0=ok, 2=block)
  check-spawn         Hook: check spawn limit before Agent tool (exit 0=ok, 2=block)
  check-destructive   Hook: block destructive Bash commands (DROP/DELETE/TRUNCATE/rm-rf)
  check-shield        Hook: LakshmanRekha injection/exfil/credential detection on Bash/Read/Write/Edit
  register        Check In: create policy file, register agent in state machine
  close           Check Out: mark agent COMPLETED, write final manifest
  quarantine list         List all QUARANTINED/ORPHAN agents with violation summary
  quarantine release <id> Human-in-the-loop release from quarantine (requires --reason)
  valve list              List all gate valve records
  valve status <id>       Show valve state, perm_mask, class_mask for an agent
  valve throttle <id>     Narrow: OPEN → THROTTLED (clears SPAWN_AGENTS)
  valve crack <id>        Narrow: → CRACKED (also clears EXEC_BASH)
  valve close <id>        Narrow: → CLOSED (perm_mask = 0, soft stop)
  valve lock <id>         Narrow: → LOCKED (perm_mask = 0 + quarantine flag)
  valve open <id>         Restore THROTTLED/CRACKED → OPEN (human only)
  init            Initialize ~/.aegis/ config and database
  statusline      Single-line status for Claude Code statusLine hook
  bg list         List background agents spawned this session
  bg ack          Acknowledge all — remove Stop hook guard for this session

Dashboard:  bun run /root/aegis/src/dashboard/server.ts
Monitor:    bun run /root/aegis/src/monitor/index.ts
`);
}

main().catch((err) => {
  console.error("AEGIS error:", err.message);
  process.exit(1);
});
