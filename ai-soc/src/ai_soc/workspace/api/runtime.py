"""Runtime dependencies for workspace API routes."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from ai_soc.contracts.models import AuthorizedSite, SiteConfig, VerifiedPrincipal


class SitePolicy(Protocol):
    def authorized_sites(self, principal: VerifiedPrincipal) -> tuple[SiteConfig, ...]: ...

    def authorize(self, principal: VerifiedPrincipal, environment_id: str) -> AuthorizedSite: ...


@dataclass(frozen=True, slots=True)
class WorkspaceRuntime:
    """Server-owned database and authorization configuration; never request supplied."""

    dsn_provider: Callable[[], str]
    site_policy: SitePolicy
    cursor_secret: bytes
    now: Callable[[], datetime] = lambda: datetime.now(UTC)

    def __post_init__(self) -> None:
        if not callable(self.dsn_provider) or not callable(self.now):
            raise TypeError("workspace runtime providers must be callable")
        if len(self.cursor_secret) < 32:
            raise ValueError("workspace cursor secret must contain at least 32 bytes")
