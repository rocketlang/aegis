# SPDX-License-Identifier: AGPL-3.0-only
# Example: LangChain agent with KAVACH gate governance
# Every tool call is intercepted by KavachGateCallback before execution.
#
# Run:
#   pip install langchain-kavachos langchain langchain-openai
#   AEGIS_TOKEN=your_token python governed_agent.py

from langchain_kavachos import KavachGateCallback, AegisClient

# Optional pre-flight: verify Aegis is reachable and within budget
client = AegisClient(base_url="http://localhost:4850")
state = client.state()
print(f"Budget: ${state['budget']['daily_spent_usd']:.4f} / ${state['budget']['daily_limit_usd']}")
if state["budget"]["breached"]:
    raise SystemExit("Daily budget breached — halting")

# Build the callback
callback = KavachGateCallback(
    base_url="http://localhost:4850",
    on_block="raise",   # raise KavachGateError if gate blocks
    dry_run=False,
    tool_name="langchain-example",
    session_id="demo-session-001",
)

# ---------- Use with any LangChain agent ----------
# from langchain_openai import ChatOpenAI
# from langchain.agents import create_react_agent, AgentExecutor
# from langchain_community.tools import ShellTool
#
# llm = ChatOpenAI(model="gpt-4o-mini")
# tools = [ShellTool()]
# agent = AgentExecutor(
#     agent=create_react_agent(llm, tools, prompt),
#     tools=tools,
# )
# result = agent.invoke({"input": "list files"}, config={"callbacks": [callback]})

# ---------- Direct tool test ----------
# Simulate what happens when a dangerous command is gated:
from langchain_kavachos import KavachGateError

test_cases = [
    ("ls -la /tmp", "should allow"),
    ("rm -rf /var/postgres", "should block DAN-4"),
]

for command, expectation in test_cases:
    print(f"\n[TEST] {command!r} ({expectation})")
    try:
        # Simulate on_tool_start firing
        callback.on_tool_start({"name": "ShellTool"}, command)
        print("  → ALLOWED")
    except KavachGateError as e:
        print(f"  → BLOCKED DAN-{e.level}: {e.reason}")

# ---------- Audit recent decisions ----------
print("\n[AUDIT] Last 5 decisions:")
result = client.audit(limit=5)
for r in result["records"]:
    print(f"  {r['status'].upper():8} DAN-{r['level']} | {r['command'][:50]}")
