"""ECS-injected secret readers for site CA material."""

from __future__ import annotations

import hashlib
import os

from ai_soc.contracts.models import SiteConfig
from ai_soc.identity.ca import SecretVersionReader
from ai_soc.live.env import site_ca_env_name


class BoundSiteCaSecretReader(SecretVersionReader):
    """Resolve pinned site CA PEM bytes from explicitly named ECS environment variables."""

    def __init__(self, sites: tuple[SiteConfig, ...]) -> None:
        self._sites = {site.ca_secret_arn: site for site in sites}

    def get_secret_value(self, *, secret_id: str, version_id: str) -> str:
        site = self._sites.get(secret_id)
        if site is None or site.ca_secret_version != version_id:
            raise ValueError("unknown site CA secret reference")
        env_name = site_ca_env_name(site.environment_id)
        pem = os.environ.get(env_name)
        if pem is None or pem == "":
            raise ValueError(f"missing site CA secret for {site.environment_id}")
        encoded = pem.encode("utf-8")
        if hashlib.sha256(encoded).hexdigest() != site.ca_sha256:
            raise ValueError("site CA digest mismatch")
        return pem
