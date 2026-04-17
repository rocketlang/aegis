import { ensureAegisDir, loadConfig, getAegisDir, getDbPath } from "../../core/config";
import { getDb } from "../../core/db";
import { existsSync, writeFileSync } from "fs";
import { join } from "path";

export default function init(_args: string[]): void {
  console.log(`\x1b[1m\x1b[36m  AEGIS Init\x1b[0m — Setting up agentic spend governance\n`);

  // 1. Create ~/.aegis directory + config
  ensureAegisDir();
  const config = loadConfig();
  console.log(`  [+] Config: ${getAegisDir()}/config.json`);

  // 2. Initialize SQLite DB
  getDb();
  console.log(`  [+] Database: ${getDbPath()}`);

  // 3. Create Claude Code hook that shells out to the `aegis` CLI (resolved via PATH)
  const hookScript = join(getAegisDir(), "pre-tool-use.sh");
  if (!existsSync(hookScript)) {
    writeFileSync(hookScript, `#!/bin/bash
# AEGIS PreToolUse hook for Claude Code
# Checks budget + spawn limits before every tool use
# Requires: aegis CLI in PATH (installed via: npm install -g @rocketlang/aegis)

INPUT=$(cat)
TOOL_NAME=$(echo "$INPUT" | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('tool_name',''))" 2>/dev/null || echo "")

if [ "$TOOL_NAME" = "Agent" ]; then
  aegis check-spawn 2>&1
else
  aegis check-budget 2>&1
fi
`, { mode: 0o755 });
    console.log(`  [+] Hook script: ${hookScript}`);
  }

  console.log(`
${"─".repeat(60)}
\x1b[1mNext steps:\x1b[0m

1. \x1b[33mStart the monitor (in background):\x1b[0m
   aegis-monitor &

2. \x1b[33mStart the dashboard:\x1b[0m
   aegis-dashboard &
   Then open: http://localhost:${config.dashboard.port}

3. \x1b[33mShow AEGIS inside Claude Code\x1b[0m (status line):
   Add to ~/.claude/settings.json:

   {
     "statusLine": {
       "type": "command",
       "command": "aegis statusline"
     }
   }

   You'll see live budget % in Claude Code's status bar.

4. \x1b[33mAdd PreToolUse hook\x1b[0m (enables budget enforcement):
   Add to ~/.claude/settings.json under "hooks.PreToolUse":

   {
     "matcher": "",
     "hooks": [{ "type": "command", "command": "bash ${hookScript}" }]
   }

5. \x1b[33mSet your plan:\x1b[0m
   # Edit ${getAegisDir()}/config.json
   # Change "plan" to one of: api, max_5x, max_20x, pro, team

6. \x1b[33mCheck status anytime:\x1b[0m
   aegis status

7. \x1b[33mEmergency kill-switch:\x1b[0m
   aegis kill          # SIGKILL (hard stop)
   aegis kill --stop   # SIGSTOP (pause, resumable)
   aegis resume        # resume paused processes

${"─".repeat(60)}
\x1b[32m  AEGIS is ready.\x1b[0m Your agents now have a budget and a kill-switch.
Docs: https://github.com/rocketlang/aegis
`);
}
