"""Indexer client — one client per environment (D43).

Queries execute as the asking principal: analyst turn JWT on direct surfaces,
environment reader on the connector edge (D11/D42).
"""
from __future__ import annotations

import time
from typing import Any, Optional

import httpx

from .config import CFG
from .env_registry import ENV_REGISTRY, EnvConfig


class IndexerError(Exception):
    pass


class Indexer:
    def __init__(self, env: EnvConfig) -> None:
        self.env_id = env.env_id
        self.alerts_index = env.alerts_index or CFG.alerts_index
        self.saved_objects_index = env.saved_objects_index or CFG.saved_objects_index
        verify: object = env.indexer_ca_path or CFG.indexer_verify_ssl
        self.http = httpx.AsyncClient(
            base_url=env.indexer_url,
            verify=verify,
            timeout=10.0,
        )
        self._mapping_cache: Optional[tuple[float, dict]] = None

    async def search(self, headers: dict[str, str], body: dict) -> dict:
        r = await self.http.post(
            f"/{self.alerts_index}/_search",
            json=body,
            headers=headers,
        )
        if r.status_code == 401:
            raise IndexerError(
                "indexer rejected the turn token (auth domain missing or expired token)"
            )
        r.raise_for_status()
        return r.json()

    async def dry_run(self, headers: dict[str, str], body: dict) -> dict:
        r = await self.http.post(
            f"/{self.alerts_index}/_validate/query?explain=true",
            json={"query": body["query"]},
            headers=headers,
        )
        r.raise_for_status()
        return r.json()

    async def cat_indices(self, headers: dict[str, str], path: str) -> list[dict[str, Any]]:
        r = await self.http.get(path, headers=headers)
        if r.status_code in (401, 403):
            raise IndexerError("indexer rejected the credential for index health")
        r.raise_for_status()
        return r.json()

    async def saved_objects_search(self, headers: dict[str, str], body: dict) -> dict:
        r = await self.http.post(
            f"/{self.saved_objects_index}/_search",
            json=body,
            headers=headers,
        )
        if r.status_code in (401, 403):
            raise IndexerError("indexer rejected the credential for saved objects")
        r.raise_for_status()
        return r.json()

    async def get_mapping(self, headers: dict[str, str]) -> Optional[dict]:
        now = time.monotonic()
        if self._mapping_cache and now - self._mapping_cache[0] < 300:
            return self._mapping_cache[1]
        r = await self.http.get(
            f"/{self.alerts_index}/_mapping", headers=headers
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


def build_indexers() -> dict[str, Indexer]:
    return {env_id: Indexer(env) for env_id, env in ENV_REGISTRY.items()}


INDEXERS = build_indexers()
INDEXER = INDEXERS[CFG.tenant]


def get_indexer(env_id: str) -> Indexer:
    try:
        return INDEXERS[env_id]
    except KeyError as exc:
        raise KeyError(f"no indexer for environment {env_id!r}") from exc
