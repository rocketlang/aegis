# xshieldai-langchain

> **🔍 Verification status (2026-05-17 IST)**
> - **Tests:** ⚠️ no pytest suite yet — planned in v1.1.0. See [PROOF-STACK.md](https://github.com/rocketlang/aegis/blob/main/PROOF-STACK.md).
> - **Examples:** ✅ 1 runnable example: [examples/governed_agent.py](examples/governed_agent.py). Run against a local AEGIS instance (`bun /root/aegis/src/dashboard/server.ts` on port 4850).
> - **Live demo:** ⚠️ planned (Tier 3)
> - **Phase-1 limits:** Callback fails open if AEGIS is unreachable (`KavachGateError` only raised on definitive DAN-3/4 block). If you require fail-closed, wrap with your own pre-flight `client.state()` check.
>
> Behaviour is end-to-end testable today: start AEGIS, run the example, fire a destructive prompt, watch the gate intercept. Automated pytest fixtures land in v1.1.0.

KavachOS DAN gate callback for LangChain agents.

Intercepts every tool call through the AEGIS KAVACH gate before execution.
Zero agent code changes — add the callback and every tool invocation is governed.

## Install

```bash
pip install xshieldai-langchain
```

## Quick start

```python
from xshieldai_langchain import KavachGateCallback

callback = KavachGateCallback(
    base_url="http://localhost:4850",   # AEGIS server
    on_block="raise",                   # raise KavachGateError on DAN-3/4
    dry_run=False,
)

# LangChain agent — pass callback in config
result = agent.invoke(
    {"input": "summarise the quarterly report"},
    config={"callbacks": [callback]},
)

# Or attach to a single tool:
result = my_tool.invoke("drop table users", config={"callbacks": [callback]})
```

## KavachGateCallback parameters

| Parameter | Default | Description |
|---|---|---|
| `base_url` | `http://localhost:4850` | AEGIS server URL |
| `token` | `$AEGIS_TOKEN` | Bearer auth token |
| `on_block` | `"raise"` | `"raise"` → KavachGateError · `"warn"` → print + continue |
| `dry_run` | `False` | Classify only — no notification, no human-in-loop polling |
| `tool_name` | `"langchain"` | Label appearing in audit records |
| `session_id` | auto-generated | Audit grouping key (one per agent session) |

## Direct client

```python
from xshieldai_langchain import AegisClient

client = AegisClient(base_url="http://localhost:4850")

# Pre-flight budget check
state = client.state()
if state["budget"]["breached"]:
    raise RuntimeError("Daily budget breached — halt")

# Manual gate call
result = client.gate(command="rm -rf /var/postgres", tool_name="my-agent")
print(result)  # {"allow": false, "level": 4, "reason": "DAN-4 catastrophic..."}

# Audit query
records = client.audit(session_id="lc-abc123", status="stop", limit=20)
```

## How it works

`KavachGateCallback.on_tool_start()` fires before any tool execution.
It POSTs to `POST /api/v1/kavach/gate` on the AEGIS server.

- **DAN-1/2**: allowed immediately, logged.
- **DAN-3**: notify approver via Telegram/WhatsApp, wait for ALLOW/STOP.
- **DAN-4**: blocked immediately, `KavachGateError` raised.

All policy is in AEGIS — the callback is a thin HTTP relay.

## AEGIS server

Run with: `bun /root/aegis/src/dashboard/server.ts`  
Default port: `4850`  
Gate endpoint: `POST /api/v1/kavach/gate`

## License

AGPL-3.0 — see [LICENSE](../../LICENSE).
