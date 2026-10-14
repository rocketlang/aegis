# @xshieldai/flow

One agentic flow, end to end. Part of the xShieldAI Posture Suite.

Every agent needs control, rails and scoping, and the xShieldAI packages provide them as separate parts: a mandate check, a cross-organisation handshake, gates before an action, kernel containment, a check on claims afterwards. This package is what lets them be read as **one flow**: it gives every action a flow, a turn and a parent, and it narrows authority at every hop so it can only shrink.

It follows section 19 of the Governed Turn Protocol (rules GTP-017 to GTP-026).

```sh
npm install @xshieldai/flow
```

## What it does (0.1.0)

| Function | Rule | What it does |
|---|---|---|
| `fromClaudeHook(input)` | GTP-018 | Flow fields for one Claude Code hook call: the session is the flow, the tool call is the turn, and the parent is the subagent that made the call or, for the main agent, the prompt it answers. No session id gives no flow, never a made-up id. |
| `stamp(event, flow)` | GTP-024 | Adds the five optional flow fields (`flow_id`, `turn_id`, `parent_turn_id`, `mandate_id`, `session_ref`) to an event. It only adds: a field the event already has is never overwritten. |
| `narrow(parent, requested)` | GTP-020 | `parent & requested`. Every hop narrows; masks must be 32-bit unsigned integers or it refuses. |
| `narrowFromParent(id, parent, requested)` | GTP-021 | Refuses when the named parent cannot be found. Missing lineage is never treated as a root. |
| `isWithin(child, parent)` | KAV-065 | True when the child holds no bit the parent lacks. |

A refusal is a `FlowRefusal` carrying the rule it enforces (`.rule`).

```js
import { fromClaudeHook, stamp, narrowFromParent } from "@xshieldai/flow";

const flow = fromClaudeHook(hookInput);      // { flow_id: "cc:<session>", turn_id: "tool:<id>", parent_turn_id: "agent:<id>" }
const event = stamp({ receipt_id, primitive: "aegis", event_type: "gate.decided" }, flow);
const mask = narrowFromParent(parentId, store.get(parentId), requested);   // throws GTP-021 if the parent is unknown
```

## What it does not do

- It enforces nothing on its own. It is pure functions with no I/O; the packages that hold the gates call it.
- It does not yet issue or verify a mandate as the root of a flow, carry an envelope across a subprocess or MCP call, or check a flow's required proof at the end. Those are later phases of the same section.

Runs under Bun and under plain Node 18+.

## License

AGPL-3.0-only. See [LICENSE](./LICENSE).
