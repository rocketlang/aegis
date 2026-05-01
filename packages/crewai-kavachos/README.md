# crewai-kavachos

**KavachOS DAN gate + budget guard for CrewAI agents.**

Governance via [AEGIS](https://kavachos.xshieldai.com) — pre-execution DAN gate on every tool call,
plus a pre-flight budget check before the crew kicks off. Zero mandatory dependency on the ANKR
platform — AEGIS communicates over HTTP.

Part of the [KavachOS](https://kavachos.xshieldai.com) agentic governance suite.

## Install

```bash
pip install crewai-kavachos
```

## Quick start

```python
from crewai import Agent, Crew, Task
from crewai_kavachos import KavachCrewAICallback, governed_kickoff

AEGIS = "http://localhost:4850"  # or your AEGIS server

# 1. Add callback to agents — gates every tool call before execution
callback = KavachCrewAICallback(base_url=AEGIS, on_block="raise")

agent = Agent(
    role="Researcher",
    goal="...",
    backstory="...",
    callbacks=[callback],
)

crew = Crew(agents=[agent], tasks=[...])

# 2. governed_kickoff = budget pre-check + crew.kickoff()
result = governed_kickoff(crew, aegis_url=AEGIS, inputs={})
```

## What it provides

| Class | What it does |
|---|---|
| `KavachCrewAICallback` | LangChain callback — intercepts every CrewAI tool call via `on_tool_start`, calls KAVACH DAN gate before execution |
| `CrewAIBudgetGuard` | Wraps `crew.kickoff()` — raises `KavachBudgetError` if daily budget is exhausted before the crew starts |
| `governed_kickoff()` | One-liner combining both: budget check + kickoff |
| `AegisClient` | Re-exported from `langchain-kavachos` — query gate, state, audit directly |
| `KavachGateError` | Raised when a tool call is blocked (DAN-1/2/3/4) |
| `KavachBudgetError` | Raised when daily budget is exhausted at crew start |

## How it works

CrewAI is built on LangChain. The `KavachCrewAICallback` subclasses `KavachGateCallback`
from `langchain-kavachos` — it fires LangChain's `on_tool_start` hook, which runs inside
CrewAI's tool dispatch loop **before** any tool executes. Policy lives in AEGIS — the callback
is a relay, not a policy engine.

If AEGIS is unreachable, both the callback and the budget guard fail open (warn, continue)
so a KavachOS outage does not block the crew entirely.

## AEGIS server

Start AEGIS (part of the KavachOS distribution):

```bash
ankr-ctl start ankr-aegis   # ANKR ecosystem
# or
PORT=4850 bun run src/dashboard/server.ts   # standalone
```

Health check: `GET http://localhost:4850/api/v1/kavach/health`

## License

AGPL-3.0 — the same license as the KAVACH kernel enforcement layer. The code governing
agents in production is auditable.
