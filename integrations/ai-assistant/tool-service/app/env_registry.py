"""Environment registry (D43). Maps gateway credential → environment config.

The environment id NEVER comes from the request payload — only from the
verified credential (D6 extended). PoC: one `lab` entry; every code path is
the N-environment path.
"""
from __future__ import annotations

import hmac
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .config import CFG

_ENV_VAR = re.compile(r"\$\{([A-Z0-9_]+)\}")


@dataclass(frozen=True)
class EnvConfig:
    env_id: str
    gateway_key: str
    indexer_url: str
    indexer_ca_path: str = ""
    reader_basic: str = ""
    reader_bearer: str = ""
    embed_ml_model_id: str = ""
    locale: str = "bilingual"
    alerts_index: str = ""
    saved_objects_index: str = ""
    dashboard_api_url: str = ""
    dashboard_executor_basic: str = ""
    manager_api_url: str = ""
    manager_ca_path: str = ""
    manager_executor_basic: str = ""
    ar_executor_basic: str = ""
    actions_tiers: tuple[str, ...] = ("dashboard",)
    manager_actions_per_hour: int = 10
    active_response_actions_per_hour: int = 5
    enabled: bool = True
  # admission overrides reserved for V3.2


def _expand(value: str) -> str:
    def repl(m: re.Match[str]) -> str:
        return os.environ.get(m.group(1), "")

    return _ENV_VAR.sub(repl, value)


def _coerce(doc: dict[str, Any]) -> EnvConfig:
    return EnvConfig(
        env_id=str(doc["env_id"]),
        gateway_key=_expand(str(doc.get("gateway_key", ""))),
        indexer_url=_expand(str(doc.get("indexer_url", CFG.indexer_url))),
        indexer_ca_path=_expand(str(doc.get("indexer_ca_path", ""))),
        reader_basic=_expand(str(doc.get("reader_basic", ""))),
        reader_bearer=_expand(str(doc.get("reader_bearer", ""))),
        embed_ml_model_id=_expand(
            str(doc.get("embed_ml_model_id", CFG.embed_ml_model_id))
        ),
        locale=str(doc.get("locale", "bilingual")),
        alerts_index=str(doc.get("alerts_index", CFG.alerts_index)),
        saved_objects_index=str(
            doc.get("saved_objects_index", CFG.saved_objects_index)
        ),
        dashboard_api_url=_expand(str(doc.get("dashboard_api_url", ""))),
        dashboard_executor_basic=_expand(str(doc.get("dashboard_executor_basic", ""))),
        manager_api_url=_expand(str(doc.get("manager_api_url", ""))),
        manager_ca_path=_expand(str(doc.get("manager_ca_path", ""))),
        manager_executor_basic=_expand(str(doc.get("manager_executor_basic", ""))),
        ar_executor_basic=_expand(str(doc.get("ar_executor_basic", ""))),
        actions_tiers=tuple(str(t) for t in doc.get("actions", ["dashboard"])),
        manager_actions_per_hour=int(doc.get("manager_actions_per_hour", 10)),
        active_response_actions_per_hour=int(
            doc.get("active_response_actions_per_hour", 5)
        ),
        enabled=bool(doc.get("enabled", True)),
    )


def _env_or(key: str, default: str) -> str:
    return os.environ.get(key, "").strip() or default


def _fallback_lab() -> EnvConfig:
    """Single-env fallback from today's WAI_* vars (harness unchanged)."""
    key = _env_or("WAI_ENV_LAB_KEY", "") or _env_or("WAI_ENV_LAB_GATEWAY_KEY", "")
    reader = _env_or("WAI_ENV_LAB_READER", "wazuh_ai_env_reader:EnvReaderLab1!")
    dash_exec = _env_or(
        "WAI_ENV_LAB_DASHBOARD_EXECUTOR",
        "wazuh_ai_dashboard_writer:DashboardWriterLab1!",
    )
    mgr_exec = _env_or("WAI_ENV_LAB_MANAGER_EXECUTOR", "wazuh-wui:MyS3cr37P450r.*-")
    ar_exec = _env_or("WAI_ENV_LAB_AR_EXECUTOR", mgr_exec)
    return EnvConfig(
        env_id=CFG.tenant,
        gateway_key=key,
        indexer_url=CFG.indexer_url,
        indexer_ca_path=CFG.indexer_ca_path,
        reader_basic=reader,
        embed_ml_model_id=CFG.embed_ml_model_id,
        alerts_index=CFG.alerts_index,
        saved_objects_index=CFG.saved_objects_index,
        dashboard_api_url=_env_or("WAI_ENV_LAB_DASHBOARD_API_URL", "https://localhost:5601"),
        dashboard_executor_basic=dash_exec,
        manager_api_url=_env_or("WAI_ENV_LAB_MANAGER_URL", "https://wazuh.manager:55000"),
        manager_ca_path=_env_or("WAI_ENV_LAB_MANAGER_CA_PATH", CFG.indexer_ca_path),
        manager_executor_basic=mgr_exec,
        ar_executor_basic=ar_exec,
        actions_tiers=tuple(
            t.strip()
            for t in _env_or("WAI_ENV_LAB_ACTIONS", "dashboard").split(",")
            if t.strip()
        ),
    )


def _load_yaml(path: Path) -> list[EnvConfig]:
    raw = yaml.safe_load(path.read_text())
    if not isinstance(raw, list):
        raise ValueError(f"{path}: expected a YAML list of environments")
    return [_coerce(doc) for doc in raw]


def load_environments() -> dict[str, EnvConfig]:
    path = (CFG.envs_file or os.environ.get("WAI_ENVS_FILE", "")).strip()
    if path:
        envs = _load_yaml(Path(path))
    else:
        envs = [_fallback_lab()]
    by_id = {e.env_id: e for e in envs}
    if len(by_id) != len(envs):
        raise ValueError("duplicate env_id in environment registry")
    return by_id


ENV_REGISTRY: dict[str, EnvConfig] = load_environments()


def resolve_by_key(key: str) -> EnvConfig | None:
    """Constant-time compare of gateway_key across all environments."""
    for env in ENV_REGISTRY.values():
        if env.gateway_key and hmac.compare_digest(key, env.gateway_key):
            return env
    return None


def get_env(env_id: str) -> EnvConfig:
    try:
        return ENV_REGISTRY[env_id]
    except KeyError as exc:
        raise KeyError(f"unknown environment {env_id!r}") from exc
