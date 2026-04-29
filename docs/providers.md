# Supported Providers

AEGIS is vendor-neutral. It reads session log files from any agentic tool that writes JSONL with usage data.

## Claude Code (Anthropic)

**Path:** `~/.claude/projects/**/*.jsonl`

**Auto-detected by:** `entrypoint: "cli"`, `version`, `slug` fields in JSONL lines.

**Usage format:**
```json
{
  "type": "assistant",
  "sessionId": "abc123",
  "message": {
    "model": "claude-opus-4-6",
    "usage": {
      "input_tokens": 1234,
      "output_tokens": 567,
      "cache_read_input_tokens": 50000,
      "cache_creation_input_tokens": 1000
    }
  },
  "timestamp": "2026-04-17T10:00:00Z"
}
```

**Agent spawn detection:** Lines where `message.content[].name === "Agent"` are counted as subagent spawns.

## OpenAI Codex CLI

**Path:** `~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl`

**Auto-detected by:** `type: "event_msg"` / `"session_meta"` / `"response_item"`, `payload.originator: "codex_exec"`.

**Usage format:**
```json
{
  "timestamp": "2026-04-17T10:00:00Z",
  "type": "event_msg",
  "payload": {
    "type": "token_count",
    "info": {
      "last_token_usage": {
        "input_tokens": 2454,
        "cached_input_tokens": 0,
        "output_tokens": 5,
        "reasoning_output_tokens": 0,
        "total_tokens": 2459
      }
    }
  }
}
```

**Session IDs:** prefixed with `codex-` to distinguish from Claude Code.

**Pricing estimates** (approximate, as of 2026):
- `gpt-5-codex` / `gpt-5`: $2.50/MTok input, $10/MTok output
- `o1`: $15/MTok input, $60/MTok output
- `o3`: $10/MTok input, $40/MTok output

Override in `pricing.ts` if you want exact figures.

## Generic JSONL

For any tool that writes JSONL with a `usage` object:

```json
{
  "session_id": "xyz",
  "model": "some-model",
  "usage": {
    "prompt_tokens": 100,
    "completion_tokens": 50
  }
}
```

AEGIS auto-detects and estimates cost using fallback pricing.

## Adding a New Provider

1. **Locate session log path** (e.g. `~/.cursor/sessions/`)
2. **Add to config** `monitor.watch_paths`
3. **Extend parser** at `src/monitor/parser.ts`:
   - Add detection rule in `detectProvider()`
   - Implement `parse<Provider>()` function
   - Map tool-specific usage fields to the `UsageRecord` interface
4. **Submit a PR** to [github.com/rocketlang/aegis](https://github.com/rocketlang/aegis)

### Contributing checklist

- [ ] Session log format is JSONL (not JSON array, not binary)
- [ ] Usage contains at minimum: input tokens, output tokens, model name
- [ ] Sample session log included in `test/fixtures/<provider>.jsonl`
- [ ] Pricing added to `src/core/pricing.ts` if model isn't already mapped
- [ ] README updated with the new provider

## Wanted

Pull requests for:

- **Cursor** — `.cursor/` session log format
- **Copilot CLI** — GitHub Copilot CLI usage
- **Devin** — Cognition Devin session logs
- **Windsurf** — Codeium Windsurf logs
- **Aider** — Aider chat history format
- **Custom agent frameworks** — LangGraph, AutoGen, CrewAI, etc.

---

## Custom Frameworks on Claude

Any agent framework that logs in Claude Code's JSONL format is automatically supported:

- **AnvilOS / TraitOS** — use `source: "anvilos"` or `provider: "traitos"` in session logs
- **Custom Claude-based agents** — any tool that produces `.jsonl` session logs with `role`/`content` fields

These are parsed identically to native Claude Code sessions.
