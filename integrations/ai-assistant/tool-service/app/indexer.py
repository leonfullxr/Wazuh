"""Indexer client. One principal only in this PoC: the asking analyst's own
turn JWT, accepted by the indexer's JWT auth domain (D11). The service holds
no standing credential that can read telemetry."""
from __future__ import annotations

import time
from typing import Any, Optional

import httpx

from .config import CFG


class IndexerError(Exception):
    pass


class Indexer:
    def __init__(self) -> None:
        # CA pinning: point WAI_INDEXER_CA_PATH at the tenant root CA (the
        # wazuh-docker cert generator writes one) and TLS is verified against
        # it. verify=False stays a lab-only fallback.
        verify: object = CFG.indexer_ca_path or CFG.indexer_verify_ssl
        self.http = httpx.AsyncClient(
            base_url=CFG.indexer_url,
            verify=verify,
            timeout=10.0,  # per-query cap
        )
        self._mapping_cache: Optional[tuple[float, dict]] = None

    def _headers(self, user_jwt: str) -> dict:
        return {"Authorization": f"Bearer {user_jwt}"}

    async def search_as_user(self, user_jwt: str, body: dict) -> dict:
        r = await self.http.post(
            f"/{CFG.alerts_index}/_search",
            json=body,
            headers=self._headers(user_jwt),
        )
        if r.status_code == 401:
            raise IndexerError("indexer rejected the turn token (auth domain missing or expired token)")
        r.raise_for_status()
        return r.json()

    async def dry_run_as_user(self, user_jwt: str, body: dict) -> dict:
        """Veracity check 2 (D24): validate the compiled query before running it."""
        r = await self.http.post(
            f"/{CFG.alerts_index}/_validate/query?explain=true",
            json={"query": body["query"]},
            headers=self._headers(user_jwt),
        )
        r.raise_for_status()
        return r.json()

    async def cat_indices_as_user(self, user_jwt: str, path: str) -> list[dict[str, Any]]:
        r = await self.http.get(path, headers=self._headers(user_jwt))
        if r.status_code in (401, 403):
            raise IndexerError("indexer rejected the turn token for index health")
        r.raise_for_status()
        return r.json()

    async def saved_objects_search_as_user(self, user_jwt: str, body: dict) -> dict:
        index = CFG.saved_objects_index
        r = await self.http.post(
            f"/{index}/_search",
            json=body,
            headers=self._headers(user_jwt),
        )
        if r.status_code in (401, 403):
            raise IndexerError("indexer rejected the turn token for saved objects")
        r.raise_for_status()
        return r.json()

    async def get_mapping(self, user_jwt: str) -> Optional[dict]:
        """Live mapping for veracity check 1 (D24), cached 5 minutes. Returns
        None when the user's role cannot read mappings, and the check is then
        reported as skipped rather than silently passed."""
        now = time.monotonic()
        if self._mapping_cache and now - self._mapping_cache[0] < 300:
            return self._mapping_cache[1]
        r = await self.http.get(
            f"/{CFG.alerts_index}/_mapping", headers=self._headers(user_jwt)
        )
        if r.status_code in (401, 403):
            return None
        r.raise_for_status()
        flat: dict[str, str] = {}

        def walk(props: dict, prefix: str) -> None:
            for name, spec in props.items():
                path = f"{prefix}{name}"
                if "properties" in spec:
                    walk(spec["properties"], f"{path}.")
                if "type" in spec:
                    flat[path] = spec["type"]
                for sub, subspec in spec.get("fields", {}).items():
                    flat[f"{path}.{sub}"] = subspec.get("type", "keyword")

        for index_body in r.json().values():
            walk(index_body.get("mappings", {}).get("properties", {}), "")
        self._mapping_cache = (now, flat)
        return flat


INDEXER = Indexer()
