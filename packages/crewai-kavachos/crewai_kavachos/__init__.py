# SPDX-License-Identifier: AGPL-3.0-only
# DEPRECATED: this package was renamed to xshieldai-crewai on 2026-05-17.
# This v1.0.1 release is a deprecation shim that re-exports from xshieldai-crewai.
# Future updates land on xshieldai-crewai only.

import warnings

warnings.warn(
    "crewai-kavachos has been renamed to xshieldai-crewai. "
    "Please install 'xshieldai-crewai' and update imports to 'from xshieldai_crewai import ...'. "
    "This shim will receive no further updates.",
    DeprecationWarning,
    stacklevel=2,
)

from xshieldai_crewai import (
    KavachCrewAICallback,
    CrewAIBudgetGuard,
    KavachBudgetError,
    KavachGateError,
    AegisClient,
    governed_kickoff,
)

__all__ = [
    "KavachCrewAICallback",
    "CrewAIBudgetGuard",
    "KavachBudgetError",
    "KavachGateError",
    "AegisClient",
    "governed_kickoff",
]
__version__ = "1.0.1"
