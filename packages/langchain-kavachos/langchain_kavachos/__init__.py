# SPDX-License-Identifier: AGPL-3.0-only
# langchain-kavachos — KavachOS governance callbacks for LangChain agents
# @rule:AEG-012 framework-agnostic: thin HTTP client, all policy in aegis
# @rule:KAV-001 every dangerous action intercepted before execution
# @rule:INF-KAV-025 LangChain callback intercepts tool calls at on_tool_start

from .gate import KavachGateCallback, KavachGateError, AegisClient

__all__ = ["KavachGateCallback", "KavachGateError", "AegisClient"]
__version__ = "1.0.0"
