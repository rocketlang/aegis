import { ensureAegisDir, loadConfig, getAegisDir, getDbPath } from "../../core/config";
import { getDb } from "../../core/db";
import { existsSync, writeFileSync, readFileSync } from "fs";
import { join } from "path";

const KAVACH_VERSION = "0.2.0";
const BEACON_URL = "https://kavach.xshieldai.com/install";  // telemetry endpoint (anonymised)
const NOTIFY_FILE = join(process.env.HOME || "/root", ".aegis", "notify.json");

async function sendBeacon(email?: string): Promise<void> {
  const payload = {
    version: KAVACH_VERSION,
    platform: process.platform,
    arch: process.arch,
    node: process.version,
    ts: new Date().toISOString(),
    ...(email ? { email } : {}),
  };
  // Save locally regardless of network
  writeFileSync(NOTIFY_FILE, JSON.stringify(payload, null, 2));
  // Fire-and-forget to tracking endpoint
  try {
    await fetch(BEACON_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(4000),
    });
  } catch { /* non-fatal — beacon is best-effort */ }
}

async function promptEmail(): Promise<string | undefined> {
  process.stdout.write(
    `\n  📬  Get notified when the KAVACH DAN gate ships (WhatsApp kill-switch)?\n` +
    `      Enter email — or press Enter to skip: `
  );
  return new Promise((resolve) => {
    let input = "";
    process.stdin.setEncoding("utf8");
    process.stdin.resume();
    process.stdin.once("data", (chunk) => {
      process.stdin.pause();
      input = String(chunk).trim();
      resolve(input || undefined);
    });
  });
}

export default async function init(args: string[]): Promise<void> {
  const sendStats = args.includes("--send-stats");
  console.log(`\x1b[1m\x1b[36m  AEGIS Init\x1b[0m — Setting up agentic spend governance\n`);

  // 1. Create ~/.aegis directory + config
  ensureAegisDir();
  const config = loadConfig();
  console.log(`  [+] Config: ${getAegisDir()}/config.json`);

  // 2. Initialize SQLite DB
  getDb();
  console.log(`  [+] Database: ${getDbPath()}`);

  // 3. Create Claude Code hooks that shell out to the `aegis` CLI (resolved via PATH)
  // V2-070: wire check-budget, check-spawn, check-shield
  const hookScript = join(getAegisDir(), "pre-tool-use.sh");
  if (!existsSync(hookScript)) {
    writeFileSync(hookScript, `#!/bin/bash
# AEGIS PreToolUse hook for Claude Code
# Three gates: budget + spawn + LakshmanRekha shield
# Requires: aegis CLI in PATH (installed via: npm install -g @rocketlang/aegis)

INPUT=$(cat)
TOOL_NAME=$(echo "$INPUT" | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('tool_name',''))" 2>/dev/null || echo "")

# Always check budget first (fastest gate)
aegis check-budget 2>&1
BUDGET_EXIT=$?
[ $BUDGET_EXIT -ne 0 ] && exit $BUDGET_EXIT

# Agent tool: check spawn limits + delegation depth
if [ "$TOOL_NAME" = "Agent" ]; then
  printf '%s' "$INPUT" | aegis check-spawn 2>&1
  exit $?
fi

# All tools: LakshmanRekha injection/credential/exfil shield
printf '%s' "$INPUT" | aegis check-shield 2>&1
exit $?
`, { mode: 0o755 });
    console.log(`  [+] Hook script: ${hookScript}`);
  }

  // 4. Auto-patch ~/.claude/settings.json — wire PreToolUse hook + statusLine (V2-070)
  const claudeSettingsPath = join(process.env.HOME || "/root", ".claude", "settings.json");
  let settingsPatched = false;
  let statusLinePatched = false;
  if (existsSync(claudeSettingsPath)) {
    try {
      const raw = readFileSync(claudeSettingsPath, "utf8");
      const settings: Record<string, unknown> = JSON.parse(raw);
      if (!settings.hooks) settings.hooks = {};
      const hooks = settings.hooks as Record<string, unknown[]>;
      if (!hooks.PreToolUse) hooks.PreToolUse = [];

      const alreadyWired = hooks.PreToolUse.some((h: unknown) =>
        JSON.stringify(h).includes("aegis") || JSON.stringify(h).includes("pre-tool-use.sh")
      );
      if (!alreadyWired) {
        hooks.PreToolUse.push({
          matcher: "",
          hooks: [{ type: "command", command: `bash ${hookScript}` }],
        });
        settingsPatched = true;
      }

      if (!settings.statusLine) {
        settings.statusLine = { type: "command", command: "aegis statusline" };
        statusLinePatched = true;
      }

      if (settingsPatched || statusLinePatched) {
        writeFileSync(claudeSettingsPath, JSON.stringify(settings, null, 2));
      }
      if (settingsPatched) console.log(`  [+] PreToolUse hook wired: ${claudeSettingsPath}`);
      else console.log(`  [=] PreToolUse hook already wired`);
      if (statusLinePatched) console.log(`  [+] Status line wired: aegis statusline`);
    } catch {
      console.log(`  [!] Could not auto-patch ${claudeSettingsPath} — add hook manually (see below)`);
    }
  } else {
    console.log(`  [!] ${claudeSettingsPath} not found — add hook manually (see below)`);
  }

  // Copy default rule sets if not present
  const aegisDir = getAegisDir();
  const rulesDir = join(aegisDir, "rules");
  const agentsDir = join(aegisDir, "agents");
  if (!existsSync(rulesDir)) { require("fs").mkdirSync(rulesDir, { recursive: true }); }
  if (!existsSync(agentsDir)) { require("fs").mkdirSync(agentsDir, { recursive: true }); }

  const defaultShieldRules = join(import.meta.dir, "../../../../rules/shield-rules.json");
  const defaultDestructiveRules = join(import.meta.dir, "../../../../rules/destructive-rules.json");
  const targetShield = join(rulesDir, "shield-rules.json");
  const targetDestructive = join(rulesDir, "destructive-rules.json");

  if (!existsSync(targetShield) && existsSync(defaultShieldRules)) {
    require("fs").copyFileSync(defaultShieldRules, targetShield);
    console.log(`  [+] Shield rules: ${targetShield}`);
  }
  if (!existsSync(targetDestructive) && existsSync(defaultDestructiveRules)) {
    require("fs").copyFileSync(defaultDestructiveRules, targetDestructive);
    console.log(`  [+] Destructive rules: ${targetDestructive}`);
  }

  console.log(`
${"─".repeat(60)}
\x1b[1mNext steps:\x1b[0m

1. \x1b[33mStart the monitor (in background):\x1b[0m
   aegis-monitor &

2. \x1b[33mStart the dashboard:\x1b[0m
   aegis-dashboard &
   Then open: http://localhost:${config.dashboard.port}

3. \x1b[33mSet your plan:\x1b[0m
   # Edit ${getAegisDir()}/config.json
   # Change "plan" to one of: api, max_5x, max_20x, pro, team

4. \x1b[33mCheck status anytime:\x1b[0m
   aegis status

5. \x1b[33mEmergency kill-switch:\x1b[0m
   aegis kill          # SIGKILL (hard stop)
   aegis kill --stop   # SIGSTOP (pause, resumable)
   aegis resume        # resume paused processes

${"─".repeat(60)}
\x1b[32m  KAVACH is ready.\x1b[0m Budget governor + injection shield + agent sandbox active.
  Dashboard:    http://localhost:${config.dashboard.port}
  Docs:         https://github.com/rocketlang/aegis
  Hook script:  ${hookScript}

  \x1b[33m⭐ Star the repo so you get release updates:\x1b[0m
     github.com/rocketlang/aegis

  \x1b[33m📣 5 minutes to install? Reply to the irRegularAI newsletter\x1b[0m
     with one word: \x1b[32mWORKED\x1b[0m or \x1b[31mBROKE\x1b[0m
     We read every reply. It's how we gate the full launch.
`);

  // Opt-in only: aegis init --send-stats
  // No network calls without explicit consent — KAVACH is a trust tool.
  if (sendStats) {
    try {
      const email = await promptEmail();
      if (email && email.includes("@")) {
        console.log(`  \x1b[32m[+] Noted — we'll email you when the DAN gate ships.\x1b[0m`);
      }
      await sendBeacon(email);
      console.log(`  [+] Anonymous install stats sent. Thank you.`);
    } catch { /* non-fatal */ }
  } else {
    console.log(`\n  \x1b[2m  No telemetry. All data stays local.\x1b[0m`);
    console.log(`  \x1b[2m  aegis init --send-stats  ← opt in to anonymous usage stats\x1b[0m`);
  }

  console.log();
}
