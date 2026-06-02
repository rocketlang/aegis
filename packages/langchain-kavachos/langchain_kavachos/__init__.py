# SPDX-License-Identifier: AGPL-3.0-only
# DEPRECATED: this package was renamed to xshieldai-langchain on 2026-05-17.
# This v1.0.1 release is a deprecation shim that re-exports from xshieldai-langchain.
# Future updates land on xshieldai-langchain only.

import warnings

warnings.warn(
    "langchain-kavachos has been renamed to xshieldai-langchain. "
    "Please install 'xshieldai-langchain' and update imports to 'from xshieldai_langchain import ...'. "
    "This shim will receive no further updates.",
    DeprecationWarning,
    stacklevel=2,
)

from xshieldai_langchain import KavachGateCallback, KavachGateError, AegisClient

__all__ = ["KavachGateCallback", "KavachGateError", "AegisClient"]
__version__ = "1.0.1"
