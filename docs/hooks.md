# Claude Code Hooks Integration

AEGIS integrates with Claude Code via the `PreToolUse` hook, enforcing budgets and spawn limits before every tool call.

## How it works

When Claude Code is about to invoke a tool (Read, Edit, Bash, Agent, etc.), it runs the configured `PreToolUse` hook first. If the hook exits non-zero, the tool call is blocked and Claude sees the error message.

AEGIS uses this to:
- **Block tool calls** when daily/weekly/session budget is exhausted
- **Block Agent spawns** when the spawn limit is reached
- **Warn** at 80%/90% budget thresholds without blocking

## Setup

After `aegis init`, add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "",
      "hooks": [{
        "type": "command",
        "command": "bash ~/.aegis/pre-tool-use.sh"
      }]
    }]
  }
}
```

The empty `matcher: ""` fires on all tool calls.

## What the hook script does

`~/.aegis/pre-tool-use.sh`:

```bash
#!/bin/bash
INPUT=$(cat)
TOOL_NAME=$(echo "$INPUT" | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('tool_name',''))")

if [ "$TOOL_NAME" = "Agent" ]; then
  aegis check-spawn
else
  aegis check-budget
fi
```

- Reads the hook input from stdin
- Extracts `tool_name`
- Routes `Agent` tool calls to spawn-limit check
- Everything else → budget check

## Exit codes

| Exit | Meaning | Claude Code behavior |
|------|---------|----------------------|
| 0 | Allow | Tool call proceeds |
| 2 | Block | Tool call blocked, stderr shown to Claude |
| other | Error | Tool call proceeds (fail-open) |

## Latency

- **Budget check:** ~30-50ms (Bun cold start + SQLite read)
- **Spawn check:** ~30-50ms

Fail-open behavior: if AEGIS is not installed or the SQLite database is unavailable, tool calls proceed. This prevents AEGIS from blocking Claude Code if its own monitor is down.

## Testing

```bash
# Test the hook manually
echo '{"tool_name": "Bash"}' | bash ~/.aegis/pre-tool-use.sh
echo "exit code: $?"

# Force a block by setting daily budget to 0
aegis budget set daily 0
echo '{"tool_name": "Bash"}' | bash ~/.aegis/pre-tool-use.sh
# exit code should be 2

# Reset
aegis budget set daily 100
```

## Disabling

Remove the `PreToolUse` entry from `~/.claude/settings.json`, or point it to `/bin/true` to effectively disable it without removing the config.
