import { addAlert, setSessionStatus, listActiveSessions } from "../../core/db";

export default function pause(args: string[], mode: "pause" | "resume"): void {
  const signal = mode === "pause" ? 19 : 18; // SIGSTOP / SIGCONT
  const label = mode === "pause" ? "Pausing" : "Resuming";

  console.log(`\x1b[33m[AEGIS] ${label} all agent processes...\x1b[0m`);

  try {
    const result = Bun.spawnSync(["pgrep", "-f", "claude"]);
    const pids = result.stdout.toString().trim().split("\n").filter(Boolean);
    const myPid = process.pid.toString();
    let count = 0;

    for (const pidStr of pids) {
      const pid = parseInt(pidStr);
      if (isNaN(pid) || pidStr === myPid) continue;
      try {
        process.kill(pid, signal);
        count++;
        console.log(`  ${label} PID ${pid}`);
      } catch { /* */ }
    }

    if (count === 0) {
      console.log("  No agent processes found.");
    } else {
      console.log(`\n[AEGIS] ${count} process(es) ${mode === "pause" ? "paused" : "resumed"}.`);
    }

    // Update DB
    const status = mode === "pause" ? "paused" : "active";
    for (const s of listActiveSessions()) {
      setSessionStatus(s.session_id, status);
    }

    addAlert({
      type: mode === "pause" ? "kill" : "budget_warning",
      severity: "info",
      message: `Manual ${mode}: ${count} processes`,
      timestamp: new Date().toISOString(),
    });
  } catch (err: any) {
    console.error(`Error: ${err.message}`);
  }
}
