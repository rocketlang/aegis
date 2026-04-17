#!/usr/bin/env bun
// AEGIS CLI — aegis status | kill | pause | resume | budget | check-budget | check-spawn | init

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
      return (await import("./commands/pause")).default(args, "resume");
    case "budget":
      return (await import("./commands/budget")).default(args);
    case "check-budget":
      return (await import("./commands/check-budget")).default(args);
    case "check-spawn":
      return (await import("./commands/check-spawn")).default(args);
    case "init":
      return (await import("./commands/init")).default(args);
    case "statusline":
      return (await import("./commands/statusline")).default(args);
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
  pause           Pause all agent processes (SIGSTOP)
  resume          Resume paused processes (SIGCONT)
  budget show     Show budget limits
  budget set      Set budget (e.g. aegis budget set daily 50)
  check-budget    Hook: check budget before tool use (exit 0=ok, 2=block)
  check-spawn     Hook: check spawn limit before Agent tool (exit 0=ok, 2=block)
  init            Initialize ~/.aegis/ config and database
  statusline      Single-line status for Claude Code statusLine hook

Dashboard:  bun run /root/aegis/src/dashboard/server.ts
Monitor:    bun run /root/aegis/src/monitor/index.ts
`);
}

main().catch((err) => {
  console.error("AEGIS error:", err.message);
  process.exit(1);
});
