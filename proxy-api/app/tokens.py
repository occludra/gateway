"""Credential store helpers shared by every provider credential path.

The gateway's own secret store is ``config/gateway.yaml`` (``providers.<name>.api_key``,
typically fed from the environment). OrcaRouter keys live there too -- this
module does not introduce a second store; it only adds classification,
masking and lifecycle metadata for stored keys.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

ORCA_KEY_PREFIX = "sk-orca-"
_MASK_KEEP = 4


@dataclass(frozen=True)
class CredentialInfo:
    """Non-secret description of a stored credential, safe to render."""

    well_formed: bool
    masked: str
    generation: int = 0
    needs_reauth: bool = False


class CredentialStore:
    """Classification and masking for credentials kept in gateway.yaml."""

    @staticmethod
    def classify(api_key: str) -> CredentialInfo:
        """Lightweight format check only -- the prefix is not proof of validity."""
        well_formed = bool(re.fullmatch(r"sk-orca-[A-Za-z0-9_\-]{8,}", api_key or ""))
        return CredentialInfo(well_formed=well_formed, masked=CredentialStore.mask(api_key))

    @staticmethod
    def mask(api_key: str) -> str:
        if not api_key:
            return ""
        if len(api_key) <= _MASK_KEEP * 2:
            return "*" * len(api_key)
        return f"{api_key[:7]}…{api_key[-_MASK_KEEP:]}"
