# xshieldai-crewai

> **🔍 Verification status (2026-05-17 IST)**
> - **Tests:** ⚠️ no pytest suite yet — planned in v1.1.0. See [PROOF-STACK.md](https://github.com/rocketlang/aegis/blob/main/PROOF-STACK.md).
> - **Examples:** ✅ 1 runnable example: [examples/governed_crew.py](examples/governed_crew.py). Run against a local AEGIS instance on port 4850.
> - **Live demo:** ⚠️ planned (Tier 3)
> - **Phase-1 limits:** Both callback and budget guard fail OPEN if AEGIS is unreachable (so a KavachOS outage does not block the crew entirely). If you require fail-closed, wrap with explicit AEGIS health checks before `governed_kickoff()`.
>
> Behaviour is end-to-end testable today: start AEGIS, run the example crew, watch DAN-3/4 tool calls intercept and budget exhaustion halt kickoff. Automated pytest fixtures land in v1.1.0.

**KavachOS DAN gate + budget guard for CrewAI agents.**

Governance via [AEGIS](https://kavachos.xshieldai.com) — pre-execution DAN gate on every tool call,
plus a pre-flight budget check before the crew kicks off. Zero mandatory dependency on the ANKR
platform — AEGIS communicates over HTTP.

Part of the [KavachOS](https://kavachos.xshieldai.com) agentic governance suite.

## Install

```bash
pip install xshieldai-crewai
```

## Quick start

```python
from crewai import Agent, Crew, Task
from xshieldai_crewai import KavachCrewAICallback, governed_kickoff

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
| `AegisClient` | Re-exported from `xshieldai-langchain` — query gate, state, audit directly |
| `KavachGateError` | Raised when a tool call is blocked (DAN-1/2/3/4) |
| `KavachBudgetError` | Raised when daily budget is exhausted at crew start |

## How it works

CrewAI is built on LangChain. The `KavachCrewAICallback` subclasses `KavachGateCallback`
from `xshieldai-langchain` — it fires LangChain's `on_tool_start` hook, which runs inside
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
