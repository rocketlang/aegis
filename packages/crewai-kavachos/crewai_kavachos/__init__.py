# SPDX-License-Identifier: AGPL-3.0-only
# crewai-kavachos — KavachOS governance for CrewAI agents
# @rule:KOS-086 CrewAI built on LangChain — on_tool_start is the correct gate point
# @rule:KOS-090 AGPL-3.0 — audit-grade license for agent governance code

from langchain_kavachos import AegisClient, KavachGateError
from .gate import KavachCrewAICallback, CrewAIBudgetGuard, KavachBudgetError, governed_kickoff

__all__ = [
    "KavachCrewAICallback",
    "CrewAIBudgetGuard",
    "KavachBudgetError",
    "KavachGateError",
    "AegisClient",
    "governed_kickoff",
]
__version__ = "1.0.0"
