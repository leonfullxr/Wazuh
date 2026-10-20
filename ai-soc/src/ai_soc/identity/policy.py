"""Per-site group-to-role mapping and effective authorization fingerprints."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import datetime

from ai_soc.contracts.canonical import policy_hash as make_policy_hash
from ai_soc.contracts.canonical import site_config_hash
from ai_soc.contracts.models import (
    AuthorizedSite,
    ErrorCode,
    IndexFamily,
    SiteConfig,
    TemplateId,
    VerifiedPrincipal,
    Visibility,
)


class SiteAuthorizationError(PermissionError):
    def __init__(self, code: ErrorCode = ErrorCode.SITE_DENIED) -> None:
        self.code = code
        super().__init__(code.value)


class MappedSitePolicy:
    """Maps only verifier-supplied groups; callers cannot provide backend roles."""

    def __init__(
        self, sites: Iterable[SiteConfig], *, now: Callable[[], datetime] | None = None
    ) -> None:
        configs = tuple(sites)
        self._sites = {site.environment_id: site for site in configs}
        if len(self._sites) != len(configs):
            raise ValueError("duplicate site environment id")
        self._now = now
        for site in configs:
            if site.enabled and (not site.group_role_map or not site.dls_attestation_version):
                raise ValueError("enabled site requires group mapping and DLS attestation")
            known_roles = {role for roles in site.group_role_map.values() for role in roles}
            if any(role not in site.role_visibility for role in known_roles):
                raise ValueError("site role mapping references an unclassified role")

    def authorized_sites(self, principal: VerifiedPrincipal) -> tuple[SiteConfig, ...]:
        if not principal.groups:
            return ()
        if self._now is not None and principal.expires_at <= self._now():
            return ()
        result: list[SiteConfig] = []
        for site in self._sites.values():
            if not site.enabled:
                continue
            roles = self._roles(site, principal.groups)
            if roles:
                result.append(site)
        return tuple(sorted(result, key=lambda site: site.environment_id))

    def authorize(self, principal: VerifiedPrincipal, environment_id: str) -> AuthorizedSite:
        if self._now is not None:
            now = self._now()
            if principal.expires_at <= now:
                raise SiteAuthorizationError(ErrorCode.AUTH_EXPIRED)
        site = self._sites.get(environment_id)
        if site is None or not site.enabled or not principal.groups:
            raise SiteAuthorizationError()
        roles = self._roles(site, principal.groups)
        if not roles:
            raise SiteAuthorizationError()
        # A role label alone cannot attest the combined DLS scope. Exact role-set
        # attestation is required; missing combinations deliberately remain unknown.
        composite_key = ",".join(roles)
        visibility = Visibility(
            site.composite_role_visibility.get(composite_key, Visibility.unknown)
        )
        # StrictModel.use_enum_values keeps StrEnum values as strings. Normalize
        # a copy for the frozen canonical helper, which deliberately uses enum
        # objects while constructing the same JSON identity.
        canonical_site = site.model_copy(
            update={
                "allowed_templates": tuple(TemplateId(value) for value in site.allowed_templates),
                "allowed_index_patterns": {
                    IndexFamily(family): patterns
                    for family, patterns in site.allowed_index_patterns.items()
                },
            }
        )
        config_digest = site_config_hash(canonical_site)
        effective = make_policy_hash(
            config_digest, roles, visibility.value, site.dls_attestation_version
        )
        return AuthorizedSite(
            config=site,
            backend_roles=roles,
            visibility=visibility,
            config_hash=config_digest,
            policy_hash=effective,
        )

    @staticmethod
    def _roles(site: SiteConfig, groups: tuple[str, ...]) -> tuple[str, ...]:
        roles = {role for group in groups for role in site.group_role_map.get(group, ())}
        return tuple(sorted(roles))
