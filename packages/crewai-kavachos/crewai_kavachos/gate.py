# SPDX-License-Identifier: AGPL-3.0-only
# @rule:KOS-086 CrewAI is LangChain-based — on_tool_start is the correct gate point
# @rule:KOS-089 zero mandatory deps on ANKR platform; AegisClient uses stdlib only
# @rule:KOS-091 CrewAIBudgetGuard checks budget BEFORE kickoff — no wasted compute
# @rule:KOS-YK-015 import from langchain-kavachos; do not re-implement gate logic
from __future__ import annotations

import uuid
from typing import Any, Dict, Optional

from langchain_kavachos import AegisClient, KavachGateCallback, KavachGateError


class KavachBudgetError(Exception):
    """Raised when the daily KAVACH budget is exhausted before a crew kicks off."""

    def __init__(self, daily_spent: float, daily_limit: float, remaining: float):
        self.daily_spent = daily_spent
        self.daily_limit = daily_limit
        self.remaining = remaining
        super().__init__(
            f"KAVACH budget exhausted before crew start: "
            f"spent={daily_spent:.4f} limit={daily_limit:.4f} remaining={remaining:.4f}"
        )


class KavachCrewAICallback(KavachGateCallback):
    """KavachOS DAN gate callback for CrewAI agents.

    Drop-in: pass an instance in the ``callbacks`` list of any CrewAI agent or tool.
    CrewAI is built on LangChain — this subclass sets CrewAI-appropriate defaults
    (tool_name, session_id prefix) and re-exports ``KavachGateError`` for caller convenience.

    Usage::

        from crewai_kavachos import KavachCrewAICallback, governed_kickoff

        # Option A — callback on individual agent
        callback = KavachCrewAICallback(base_url="http://localhost:4850")
        agent = Agent(..., callbacks=[callback])

        # Option B — governed_kickoff wraps the whole crew
        result = governed_kickoff(crew, aegis_url="http://localhost:4850")
    """

    def __init__(
        self,
        base_url: str = "http://localhost:4850",
        token: Optional[str] = None,
        on_block: str = "raise",
        dry_run: bool = False,
        session_id: Optional[str] = None,
    ):
        super().__init__(
            base_url=base_url,
            token=token,
            on_block=on_block,
            dry_run=dry_run,
            tool_name="crewai",
            session_id=session_id or f"crew-{uuid.uuid4().hex[:12]}",
        )


class CrewAIBudgetGuard:
    """Pre-flight budget check for CrewAI crews.

    Wraps ``crew.kickoff()`` — checks AEGIS budget state before the crew starts.
    Raises ``KavachBudgetError`` immediately if the daily budget is exhausted,
    avoiding wasted compute from a crew that would be halted mid-task anyway.

    Usage::

        from crewai_kavachos import CrewAIBudgetGuard

        guard = CrewAIBudgetGuard(base_url="http://localhost:4850")
        result = guard.kickoff(crew, inputs={"topic": "AI safety"})
    """

    def __init__(
        self,
        base_url: str = "http://localhost:4850",
        token: Optional[str] = None,
        on_block: str = "raise",
    ):
        if on_block not in ("raise", "warn"):
            raise ValueError("on_block must be 'raise' or 'warn'")
        self.client = AegisClient(base_url=base_url, token=token)
        self.on_block = on_block

    def _check_budget(self) -> None:
        # @rule:KOS-091 pre-flight: abort before crew starts if budget breached
        try:
            state = self.client.state()
        except RuntimeError:
            # AEGIS unreachable — fail open, let crew run
            import warnings
            warnings.warn("[CrewAIBudgetGuard] AEGIS unreachable — proceeding unguarded", stacklevel=3)
            return

        if state.get("breached", False):
            spent = state.get("daily_spent", 0.0)
            limit = state.get("daily_limit", 0.0)
            remaining = state.get("remaining", 0.0)
            if self.on_block == "raise":
                raise KavachBudgetError(daily_spent=spent, daily_limit=limit, remaining=remaining)
            else:
                import warnings
                warnings.warn(
                    f"[CrewAIBudgetGuard] Budget breached (spent={spent:.4f}) — continuing (on_block=warn)",
                    stacklevel=3,
                )

    def kickoff(self, crew: Any, *, inputs: Optional[Dict[str, Any]] = None) -> Any:
        """Run budget pre-check then delegate to crew.kickoff()."""
        self._check_budget()
        if inputs is not None:
            return crew.kickoff(inputs=inputs)
        return crew.kickoff()


def governed_kickoff(
    crew: Any,
    *,
    aegis_url: str = "http://localhost:4850",
    token: Optional[str] = None,
    on_block: str = "raise",
    inputs: Optional[Dict[str, Any]] = None,
) -> Any:
    """One-liner: budget pre-check + run crew.kickoff().

    Does NOT auto-inject the callback into agents (CrewAI injects callbacks at
    agent construction time). Use ``KavachCrewAICallback`` on each Agent for
    per-tool gate enforcement. This helper handles crew-level budget only.

    Usage::

        from crewai_kavachos import governed_kickoff

        result = governed_kickoff(crew, aegis_url="http://localhost:4850", inputs={"topic": "safety"})
    """
    guard = CrewAIBudgetGuard(base_url=aegis_url, token=token, on_block=on_block)
    return guard.kickoff(crew, inputs=inputs)
