// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

import { addAlert, setSessionStatus, listActiveSessions } from "../../core/db";

export default function kill(args: string[]): void {
  const useStop = args.includes("--stop") || args.includes("-s");
  const sessionArg = args.indexOf("--session");
  const sessionId = sessionArg >= 0 ? args[sessionArg + 1] : null;
  const signal = useStop ? "SIGSTOP" : "SIGKILL";
  const sigNum = useStop ? 19 : 9;
  const action = useStop ? "Pausing" : "Killing";

  console.log(`\x1b[31m[AEGIS] ${action} agent processes...\x1b[0m`);

  try {
    const result = Bun.spawnSync(["pgrep", "-f", "claude"]);
    const pids = result.stdout.toString().trim().split("\n").filter(Boolean);
    const myPid = process.pid.toString();
    let killed = 0;

    for (const pidStr of pids) {
      const pid = parseInt(pidStr);
      if (isNaN(pid) || pidStr === myPid) continue;
      try {
        process.kill(pid, sigNum);
        killed++;
        console.log(`  ${action} PID ${pid}`);
      } catch (e: any) {
        console.log(`  PID ${pid}: ${e.message}`);
      }
    }

    // Also check for other agentic tools
    for (const procName of ["cursor", "copilot", "codex", "devin"]) {
      try {
        const r = Bun.spawnSync(["pgrep", "-f", procName]);
        const agentPids = r.stdout.toString().trim().split("\n").filter(Boolean);
        for (const pidStr of agentPids) {
          const pid = parseInt(pidStr);
          if (isNaN(pid) || pidStr === myPid) continue;
          try {
            process.kill(pid, sigNum);
            killed++;
            console.log(`  ${action} ${procName} PID ${pid}`);
          } catch { /* */ }
        }
      } catch { /* */ }
    }

    if (killed === 0) {
      console.log("  No agent processes found.");
    } else {
      console.log(`\n\x1b[31m[AEGIS] ${killed} process(es) ${useStop ? "paused" : "killed"}.\x1b[0m`);
    }

    // Update session statuses
    const status = useStop ? "paused" : "killed";
    if (sessionId) {
      setSessionStatus(sessionId, status);
    } else {
      for (const s of listActiveSessions()) {
        setSessionStatus(s.session_id, status);
      }
    }

    // Log the kill
    addAlert({
      type: "kill",
      severity: "critical",
      message: `Manual ${signal}: ${killed} processes ${useStop ? "paused" : "killed"}${sessionId ? ` (session ${sessionId.slice(0, 8)})` : " (all)"}`,
      session_id: sessionId || undefined,
      timestamp: new Date().toISOString(),
    });
  } catch (err: any) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  }
}
