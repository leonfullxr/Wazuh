"""Minimal environment registry for auth-shim (V3.6).

Loads the same environments.yaml shape as the tool-service gateway. The shim
only needs indexer_url and env_id to verify credentials via authinfo.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

_ENV_VAR = re.compile(r"\$\{([A-Z0-9_]+)\}")


@dataclass(frozen=True)
class EnvEntry:
    env_id: str
    indexer_url: str
    indexer_ca_path: str = ""


def _expand(value: str) -> str:
    def repl(m: re.Match[str]) -> str:
        return os.environ.get(m.group(1), "")

    return _ENV_VAR.sub(repl, value)


def _coerce(doc: dict[str, Any]) -> EnvEntry:
    return EnvEntry(
        env_id=str(doc["env_id"]),
        indexer_url=_expand(str(doc.get("indexer_url", "https://wazuh.indexer:9200"))),
        indexer_ca_path=_expand(str(doc.get("indexer_ca_path", ""))),
    )


def _fallback_lab() -> EnvEntry:
    return EnvEntry(
        env_id=os.environ.get("SHIM_DEFAULT_ENV_ID", os.environ.get("SHIM_TENANT", "lab")),
        indexer_url=os.environ.get("SHIM_INDEXER_URL", "https://wazuh.indexer:9200"),
        indexer_ca_path=os.environ.get("SHIM_INDEXER_CA_PATH", ""),
    )


def load_environments() -> dict[str, EnvEntry]:
    path = os.environ.get("SHIM_ENVS_FILE", "").strip()
    if path:
        raw = yaml.safe_load(Path(path).read_text())
        if not isinstance(raw, list):
            raise ValueError(f"{path}: expected a YAML list of environments")
        envs = [_coerce(doc) for doc in raw]
    else:
        envs = [_fallback_lab()]
    by_id = {e.env_id: e for e in envs}
    if len(by_id) != len(envs):
        raise ValueError("duplicate env_id in environment registry")
    return by_id
