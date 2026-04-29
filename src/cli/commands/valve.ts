// AEGIS CLI — valve: inspect and control gate valve state per agent
// @rule:KAV-063 Gate valve: OPEN → THROTTLED → CRACKED → CLOSED → LOCKED
// @rule:KAV-066 LOCKED requires human release
//
// Usage:
//   aegis valve status <agent-id>
//   aegis valve list
//   aegis valve throttle <agent-id> [--reason "..."]
//   aegis valve crack <agent-id> [--reason "..."]
//   aegis valve close <agent-id> [--reason "..."]
//   aegis valve lock <agent-id> [--reason "..."]
//   aegis valve open <agent-id> [--released-by "..."]

import { existsSync, readdirSync } from "fs";
import { join } from "path";
import { getAegisDir } from "../../core/config";
import {
  readValve, throttleValve, crackValve, closeValve, lockValve, openValve,
  type GateValveRecord,
} from "../../kavach/gate-valve";
import { renderPermMask } from "../../kavach/perm-mask";
import { renderClassMask } from "../../kavach/class-mask";

function getValveDir(): string {
  return join(getAegisDir(), "agents");
}

function listAllValves(): GateValveRecord[] {
  const dir = getValveDir();
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => f.endsWith(".valve.json"))
    .map((f) => {
      try {
        const { readFileSync } = require("fs");
        return JSON.parse(readFileSync(join(dir, f), "utf-8")) as GateValveRecord;
      } catch { return null; }
    })
    .filter(Boolean) as GateValveRecord[];
}

const STATE_EMOJI: Record<string, string> = {
  OPEN: "🟢",
  THROTTLED: "🟡",
  CRACKED: "🟠",
  CLOSED: "🔴",
  LOCKED: "🛑",
};

function printValve(v: GateValveRecord): void {
  const emoji = STATE_EMOJI[v.state] ?? "⚪";
  console.log(`
${emoji} Agent: ${v.agent_id}
  State         : ${v.state}
  Violations    : ${v.violation_count}
  Loop count    : ${v.loop_count}
  Declared perm : 0x${v.declared_perm_mask.toString(16).padStart(8, "0")} (${renderPermMask(v.declared_perm_mask)})
  Effective perm: 0x${v.effective_perm_mask.toString(16).padStart(8, "0")} (${renderPermMask(v.effective_perm_mask)})
  Declared class: 0x${v.declared_class_mask.toString(16).padStart(4, "0")} (${renderClassMask(v.declared_class_mask)})
  Effective cls : 0x${v.effective_class_mask.toString(16).padStart(4, "0")} (${renderClassMask(v.effective_class_mask)})${
    v.narrowed_at ? `\n  Narrowed at   : ${v.narrowed_at}\n  Narrowed by   : ${v.narrowed_reason}` : ""
  }${
    v.locked_by ? `\n  Locked by     : ${v.locked_by} at ${v.locked_at}` : ""
  }${
    v.quarantine_flag ? "\n  ⚠️  QUARANTINE FLAG SET" : ""
  }
`);
}

function parseArgs(args: string[]): { reason: string; releasedBy: string } {
  let reason = "manual operator action";
  let releasedBy = "operator";
  for (let i = 0; i < args.length; i++) {
    if ((args[i] === "--reason" || args[i] === "-r") && args[i + 1]) {
      reason = args[++i];
    }
    if ((args[i] === "--released-by" || args[i] === "--by") && args[i + 1]) {
      releasedBy = args[++i];
    }
  }
  return { reason, releasedBy };
}

export default function valveCommand(args: string[]): void {
  const sub = args[0];
  const agentId = args[1];
  const { reason, releasedBy } = parseArgs(args.slice(2));

  switch (sub) {
    case "list": {
      const valves = listAllValves();
      if (valves.length === 0) {
        console.log("No valve records found.");
        return;
      }
      console.log(`\n${valves.length} valve record(s):\n`);
      for (const v of valves.sort((a, b) => a.state.localeCompare(b.state))) {
        const emoji = STATE_EMOJI[v.state] ?? "⚪";
        const perm = v.effective_perm_mask === v.declared_perm_mask
          ? `0x${v.effective_perm_mask.toString(16)}`
          : `0x${v.declared_perm_mask.toString(16)} → 0x${v.effective_perm_mask.toString(16)} (narrowed)`;
        console.log(
          `  ${emoji} ${v.state.padEnd(10)} ${v.agent_id.slice(0, 24).padEnd(26)} ` +
          `violations=${v.violation_count} loops=${v.loop_count} perm=${perm}`
        );
      }
      console.log();
      return;
    }

    case "status": {
      if (!agentId) { console.error("Usage: aegis valve status <agent-id>"); process.exit(1); }
      printValve(readValve(agentId));
      return;
    }

    case "throttle": {
      if (!agentId) { console.error("Usage: aegis valve throttle <agent-id>"); process.exit(1); }
      const result = throttleValve(agentId, reason);
      printValve(result);
      return;
    }

    case "crack": {
      if (!agentId) { console.error("Usage: aegis valve crack <agent-id>"); process.exit(1); }
      const result = crackValve(agentId, reason);
      printValve(result);
      return;
    }

    case "close": {
      if (!agentId) { console.error("Usage: aegis valve close <agent-id>"); process.exit(1); }
      const result = closeValve(agentId, reason);
      printValve(result);
      return;
    }

    case "lock": {
      if (!agentId) { console.error("Usage: aegis valve lock <agent-id>"); process.exit(1); }
      const result = lockValve(agentId, reason, releasedBy);
      printValve(result);
      return;
    }

    case "open": {
      if (!agentId) { console.error("Usage: aegis valve open <agent-id> --released-by <name>"); process.exit(1); }
      try {
        const result = openValve(agentId, releasedBy);
        printValve(result);
      } catch (err: any) {
        console.error(`\n❌ ${err.message}\n`);
        console.error("  CLOSED/LOCKED agents must be released via: aegis quarantine release <id>\n");
        process.exit(1);
      }
      return;
    }

    default:
      console.log(`
AEGIS Gate Valve — control agent capability narrowing

Commands:
  aegis valve list                          List all valve records
  aegis valve status <agent-id>             Show valve state + masks
  aegis valve throttle <agent-id>           OPEN → THROTTLED (clears SPAWN_AGENTS)
  aegis valve crack <agent-id>              → CRACKED (also clears EXEC_BASH)
  aegis valve close <agent-id>              → CLOSED (perm_mask = 0, soft stop)
  aegis valve lock <agent-id>               → LOCKED (perm_mask = 0 + quarantine flag)
  aegis valve open <agent-id>               Restore THROTTLED/CRACKED → OPEN

Options:
  --reason "..."    Reason for transition (logged to valve record)
  --released-by     Identity of operator releasing the valve

States:
  🟢 OPEN       All declared capabilities active
  🟡 THROTTLED  SPAWN_AGENTS cleared
  🟠 CRACKED    SPAWN_AGENTS + EXEC_BASH cleared (read-only)
  🔴 CLOSED     perm_mask = 0 (soft stop)
  🛑 LOCKED     perm_mask = 0 + quarantine flag (human release only)
`);
  }
}
