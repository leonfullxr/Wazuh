"""Canonical, pinned execution requests; freezing never opens account material."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from ai_soc.workspace.model.cli_profile import INSTRUCTIONS, CodexProfile, profile_material
from ai_soc.workspace.model.cli_provider import provider_wire_schema
from ai_soc.workspace.model.schemas import FrozenIncidentPack

DOMAIN = b"ai-soc.narrative-generation.v1\x00"
PROMPT_PREFIX = (
    b"Frozen incident evidence JSON follows. Return only the schema-conforming JSON object.\n"
)
CODE_FILES = (
    "bundle.py",
    "narrate.py",
    "guardian.py",
    "worker.py",
    "cli_provider.py",
    "cli_profile.py",
    "cli_process.py",
    "cli_broker.py",
    "cli_transport.py",
    "cli_credentials.py",
    "pack.py",
    "schemas.py",
    "validation.py",
)


def canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


@dataclass(frozen=True, slots=True)
class FrozenExecution:
    prompt: bytes
    schema: bytes
    instructions: bytes
    catalog: bytes
    material: dict[str, Any]

    def digest(self, pack_digest: str) -> str:
        return sha256(
            DOMAIN
            + canonical(
                {
                    "pack_digest": pack_digest,
                    "prompt_sha256": sha256(self.prompt),
                    "schema_sha256": sha256(self.schema),
                    "instructions_sha256": sha256(self.instructions),
                    "catalog_sha256": sha256(self.catalog),
                    "execution": self.material,
                }
            )
        )


def execution_material(profile: CodexProfile) -> dict[str, Any]:
    directory = Path(__file__).parent
    return {
        "version": "workspace.narrative-execution.v1",
        "profile": profile_material(profile),
        "credential_source": {"kind": "existing_local_codex", "path": profile.auth_path},
        "code": {name: sha256((directory / name).read_bytes()) for name in CODE_FILES},
    }


def freeze_execution(pack: FrozenIncidentPack, profile: CodexProfile) -> FrozenExecution:
    catalog = (profile.project_root / profile.catalog_path).read_bytes()
    if sha256(catalog) != profile.catalog_sha256:
        raise ValueError("catalog_pin_mismatch")
    return FrozenExecution(
        PROMPT_PREFIX + pack.canonical_bytes(),
        canonical(provider_wire_schema()),
        INSTRUCTIONS.encode(),
        catalog,
        execution_material(profile),
    )


def freeze_provider_execution(
    pack: FrozenIncidentPack, *, provider_id: str, model_id: str
) -> FrozenExecution:
    """Freeze a tool-free provider request without personal-account material."""
    identity = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}")
    if identity.fullmatch(provider_id) is None or identity.fullmatch(model_id) is None:
        raise ValueError("invalid_narrative_provider_identity")
    return FrozenExecution(
        PROMPT_PREFIX + pack.canonical_bytes(),
        canonical(provider_wire_schema()),
        b"",
        b"",
        {
            "version": "workspace.narrative-provider-execution.v1",
            "provider_id": provider_id,
            "model_id": model_id,
        },
    )


def supported_provider_execution(
    execution: FrozenExecution, *, provider_id: str, model_id: str
) -> bool:
    """Require retries to use the provider identity frozen during preparation."""
    return (
        execution.material
        == {
            "version": "workspace.narrative-provider-execution.v1",
            "provider_id": provider_id,
            "model_id": model_id,
        }
        and execution.schema == canonical(provider_wire_schema())
        and execution.instructions == b""
        and execution.catalog == b""
    )


def supported_execution(execution: FrozenExecution, profile: CodexProfile) -> bool:
    try:
        return (
            0 < profile.timeout_seconds <= 120
            and 0 < profile.stdin_limit <= 131072
            and 0 < profile.stdout_limit <= 262144
            and 0 < profile.stderr_limit <= 16384
            and execution.material == execution_material(profile)
            and execution.schema == canonical(provider_wire_schema())
            and execution.instructions == INSTRUCTIONS.encode()
            and sha256(execution.catalog) == profile.catalog_sha256
        )
    except (OSError, ValueError):
        return False


def rehydrate_pack(raw: bytes, digest: str) -> FrozenIncidentPack:
    value = json.loads(raw)
    if not isinstance(value, dict) or "content_digest" in value:
        raise ValueError("invalid_frozen_pack")
    material = cast(dict[str, Any], value)
    pack = FrozenIncidentPack.model_validate_json(canonical({**material, "content_digest": digest}))
    if pack.canonical_bytes() != raw:
        raise ValueError("noncanonical_frozen_pack")
    return pack
