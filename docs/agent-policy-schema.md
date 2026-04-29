# AEGIS Agent Policy Schema

**Schema version:** `aegis-agent-policy-v1`  
**File location:** `~/.aegis/agents/{agent-id}.json`

Each agent that interacts with Claude Code tools must have a policy file. Policies are loaded at agent registration and enforced on every tool call via the PreToolUse hook.

---

## Fields

### Identity

| Field | Type | Required | Description |
|---|---|---|---|
| `schema_version` | `string` | ✅ | Must be `"aegis-agent-policy-v1"` |
| `agent_id` | `string` | ✅ | Unique identifier for this agent. Used for registry lookup and budget attribution. |
| `_comment` | `string` | — | Human description of the agent's role (not parsed). |

### Permission Bitmask

| Field | Type | Description |
|---|---|---|
| `perm_mask` | `integer` | Bitmask of allowed capabilities. Computed from `tools_allowed`/`tools_denied` at registration. Bit definitions in `src/sandbox/bitmask-schema.ts`. |
| `class_mask` | `integer` | Path/data class bits. Controls which filesystem classes the agent can access. |

**perm_mask bits:**

| Bit | Name | Value |
|---|---|---|
| 0 | `PERM_READ_FILES` | 1 |
| 1 | `PERM_WRITE_FILES` | 2 |
| 2 | `PERM_BASH_EXEC` | 4 |
| 3 | `PERM_SPAWN_AGENTS` | 8 |
| 4 | `PERM_NETWORK_ACCESS` | 16 |
| 5 | `PERM_DB_ACCESS` | 32 |
| 6 | `PERM_WEB_FETCH` | 64 |
| 7 | `PERM_MCP_TOOLS` | 128 |

### Tool Scope

| Field | Type | Description |
|---|---|---|
| `tools_allowed` | `string[]` | Allowlist of Claude Code tool names (e.g. `["Read", "Write", "Bash"]`). If empty, all tools are permitted (maximum surface — triggers `KAV-YK-013` MVT warning). |
| `tools_denied` | `string[]` | Denylist of tool names. Applied after `tools_allowed`. Takes precedence. |

Tool names match Claude Code's tool identifiers: `Read`, `Write`, `Edit`, `Bash`, `Agent`, `WebFetch`, `WebSearch`, `NotebookEdit`.

### Path Scope

| Field | Type | Description |
|---|---|---|
| `path_scope` | `string[]` | Allowed filesystem paths. Deny-first: only paths under these prefixes are accessible. Empty = no restriction. |
| `path_deny` | `string[]` | Blocked filesystem paths. Always denied regardless of `path_scope`. |

### Bash Scope

| Field | Type | Description |
|---|---|---|
| `bash_allowlist` | `string[]` | Allowed Bash command prefixes (first token). If non-empty, only these commands are permitted. |
| `bash_denylist` | `string[]` | Blocked Bash command strings. Always blocked regardless of allowlist. |

### Database Scope

| Field | Type | Description |
|---|---|---|
| `db_scope` | `string[]` | Allowed database names. Blocks `psql`, `--dbname`, `-d` flags pointing to other databases. Empty = no restriction. |

### Budget + Spawn Limits

| Field | Type | Description |
|---|---|---|
| `budget_cap_usd` | `number` | Maximum USD spend for this agent across its lifetime. Set to `0` for unlimited (not recommended). |
| `max_depth` | `integer` | Maximum sub-agent spawn depth. `0` = cannot spawn children. |
| `violation_threshold` | `integer` | Number of policy violations before automatic quarantine. |

### Network

| Field | Type | Description |
|---|---|---|
| `network_allowed` | `boolean` | Whether the agent may make outbound network calls (WebFetch, WebSearch, curl). |

---

## Identity Confidence Levels

AEGIS resolves agent identity at registration with a confidence score that affects enforcement strictness:

| Level | How resolved | Enforcement |
|---|---|---|
| `declared` | `# AEGIS-AGENT:` magic line in Claude Code task prompt | Full policy applied |
| `convention` | Agent ID inferred from naming convention | Full policy applied |
| `fingerprint` | SHA-256 fingerprint of task description | Reduced `violation_threshold` |
| `unknown` | No identity signal found | `violation_threshold = 1`; spawn blocked |

---

## Example Policies

Three starter policies are included in `examples/agents/`:

**`example-worker.json`** — read/write/bash worker, no network, no spawning, $1 cap  
**`example-compliance-auditor.json`** — read-only auditor, no write, $0.50 cap  
**`example-unknown-agent.json`** — minimal surface policy for unidentified agents  

---

## Gate Valve

At runtime, AEGIS applies progressive permission narrowing via `perm_mask` without quarantine:

- 1st violation → `PERM_SPAWN_AGENTS` cleared
- Budget ≥ 80% → `PERM_NETWORK_ACCESS` cleared
- Loop count > 50 → `PERM_BASH_EXEC` + `PERM_SPAWN_AGENTS` cleared

Use `aegis mask-log <agent-id>` to view the full gate valve history for any agent.
Use `aegis restore-mask <agent-id>` to restore cleared bits (human-only operation, logged).

---

## Force-Close Levels

When violations exceed threshold or the watchdog detects anomalous behaviour, AEGIS escalates through four force-close levels:

| Level | Name | Action |
|---|---|---|
| L1 | Soft Stop | `requestStop()` — checked at next tool call |
| L2 | Suspend | SIGSTOP to process group |
| L3 | Kill | SIGKILL to process group |
| L4 | Quarantine | Kill + write quarantine state + resume manifest |

Override token to bypass destructive gate (level 0): append `# AEGIS-DESTRUCTIVE-CONFIRMED` to the command.
