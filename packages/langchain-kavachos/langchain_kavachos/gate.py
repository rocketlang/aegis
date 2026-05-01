# SPDX-License-Identifier: AGPL-3.0-only
# @rule:KAV-001 every dangerous action intercepted before execution
# @rule:AEG-011 framework-agnostic: thin HTTP client, all policy in aegis
# @rule:AEG-012 LangChain adapter is the deployment surface for aegis governance
# @rule:INF-KAV-025 on_tool_start fires before any tool execution — correct interception point
from __future__ import annotations

import json
import os
import time
import uuid
from typing import Any, Dict, Optional, Union
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


class KavachGateError(Exception):
    """Raised when the KAVACH gate blocks an action."""

    def __init__(self, command: str, level: int, reason: str, approval_id: Optional[str] = None):
        self.command = command
        self.level = level
        self.reason = reason
        self.approval_id = approval_id
        super().__init__(
            f"KAVACH blocked (DAN-{level}): {reason}"
            + (f" [approval_id={approval_id}]" if approval_id else "")
        )


class AegisClient:
    """Thin HTTP client for the AEGIS KAVACH gate API.

    All policy is enforced in the AEGIS server — this client just relays calls.
    stdlib only: no httpx/requests dependency.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:4850",
        token: Optional[str] = None,
        timeout: int = 30,
    ):
        self.base_url = base_url.rstrip("/")
        self.token = token or os.environ.get("AEGIS_TOKEN")
        self.timeout = timeout

    def _headers(self) -> Dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def _post(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
        data = json.dumps(payload).encode()
        req = Request(url, data=data, headers=self._headers(), method="POST")
        try:
            with urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read())
        except HTTPError as e:
            body = e.read().decode(errors="replace")
            raise RuntimeError(f"Aegis HTTP {e.code} at {url}: {body}") from e
        except URLError as e:
            raise RuntimeError(f"Cannot reach Aegis at {url}: {e.reason}") from e

    def _get(self, path: str, params: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        qs = ""
        if params:
            from urllib.parse import urlencode
            qs = "?" + urlencode({k: v for k, v in params.items() if v is not None})
        url = f"{self.base_url}{path}{qs}"
        req = Request(url, headers={k: v for k, v in self._headers().items() if k != "Content-Type"})
        try:
            with urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read())
        except HTTPError as e:
            body = e.read().decode(errors="replace")
            raise RuntimeError(f"Aegis HTTP {e.code} at {url}: {body}") from e
        except URLError as e:
            raise RuntimeError(f"Cannot reach Aegis at {url}: {e.reason}") from e

    def gate(
        self,
        command: str,
        tool_name: str = "langchain",
        session_id: Optional[str] = None,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """POST /api/v1/kavach/gate — returns gate result dict."""
        return self._post(
            "/api/v1/kavach/gate",
            {
                "command": command,
                "tool_name": tool_name,
                "session_id": session_id,
                "dry_run": dry_run,
            },
        )

    def health(self) -> Dict[str, Any]:
        return self._get("/api/v1/kavach/health")

    def state(self) -> Dict[str, Any]:
        return self._get("/api/v1/kavach/state")

    def audit(
        self,
        session_id: Optional[str] = None,
        status: Optional[str] = None,
        level: Optional[int] = None,
        limit: int = 50,
    ) -> Dict[str, Any]:
        params: Dict[str, str] = {"limit": str(limit)}
        if session_id:
            params["session_id"] = session_id
        if status:
            params["status"] = status
        if level is not None:
            params["level"] = str(level)
        return self._get("/api/v1/kavach/audit", params)


class KavachGateCallback:
    """LangChain callback handler that intercepts tool calls through the KAVACH DAN gate.

    Drop-in: pass an instance in ``callbacks=[KavachGateCallback()]`` on any LangChain
    agent or tool invocation. No agent code changes needed beyond adding the callback.

    Usage::

        from langchain_kavachos import KavachGateCallback

        callback = KavachGateCallback(
            base_url="http://localhost:4850",
            on_block="raise",       # or "warn"
            dry_run=False,
        )

        result = agent.invoke({"input": "drop all backups"}, config={"callbacks": [callback]})
    """

    def __init__(
        self,
        base_url: str = "http://localhost:4850",
        token: Optional[str] = None,
        on_block: str = "raise",
        dry_run: bool = False,
        tool_name: str = "langchain",
        session_id: Optional[str] = None,
    ):
        """
        Args:
            base_url: AEGIS server URL.
            token: Bearer token (or set AEGIS_TOKEN env var).
            on_block: ``"raise"`` (raise KavachGateError) or ``"warn"`` (print warning, continue).
            dry_run: Classify only — no notification, no polling.
            tool_name: Label appearing in audit records.
            session_id: Audit grouping key. Auto-generated per callback instance if not set.
        """
        if on_block not in ("raise", "warn"):
            raise ValueError("on_block must be 'raise' or 'warn'")
        self.client = AegisClient(base_url=base_url, token=token)
        self.on_block = on_block
        self.dry_run = dry_run
        self.tool_name = tool_name
        self.session_id = session_id or f"lc-{uuid.uuid4().hex[:12]}"

    # ---- LangChain BaseCallbackHandler interface (duck-typed) ----

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        tags: Optional[list] = None,
        metadata: Optional[Dict[str, Any]] = None,
        inputs: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        """Intercept tool invocation before execution — the correct KAVACH gate point."""
        tool_name = serialized.get("name", self.tool_name) if serialized else self.tool_name
        command = input_str if isinstance(input_str, str) else json.dumps(input_str)

        try:
            result = self.client.gate(
                command=command,
                tool_name=tool_name,
                session_id=self.session_id,
                dry_run=self.dry_run,
            )
        except RuntimeError as e:
            # Aegis unreachable — fail open (log only) to avoid blocking all tooling
            import warnings
            warnings.warn(f"[KavachGateCallback] Aegis unreachable — proceeding unguarded: {e}", stacklevel=2)
            return

        if not result.get("allow", True):
            level = result.get("level", 0)
            reason = result.get("reason", "blocked")
            approval_id = result.get("approval_id")

            if self.on_block == "raise":
                raise KavachGateError(command=command, level=level, reason=reason, approval_id=approval_id)
            else:
                import warnings
                warnings.warn(
                    f"[KavachGateCallback] KAVACH blocked DAN-{level}: {reason} — continuing (on_block=warn)",
                    stacklevel=2,
                )

    def on_tool_end(
        self,
        output: str,
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        pass  # post-execution hook — reserved for future telemetry

    def on_tool_error(
        self,
        error: Union[Exception, KeyboardInterrupt],
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        pass  # error path — no gate action needed
