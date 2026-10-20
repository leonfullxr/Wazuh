"""Named environment inputs for live boot; rejects ambient reads."""

from __future__ import annotations

import base64
import binascii
import json
import os
from collections.abc import Mapping
from hashlib import sha256
from pathlib import Path
from typing import Final

from ai_soc.live.sealed import LiveSealedDocument

_ALLOWED_PREFIXES: Final = (
    "AWS_REGION",
    "AWS_EC2_METADATA_DISABLED",
    "SOC_",
    "OTEL_",
)
_ALLOWED_EXACT: Final = frozenset(
    {
        "AWS_REGION",
        "AWS_EC2_METADATA_DISABLED",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "SOC_DYNAMODB_ENDPOINT_URL",
        "SOC_BEDROCK_ENDPOINT_URL",
        "SOC_KMS_ENDPOINT_URL",
        "SOC_SQS_ENDPOINT_URL",
    }
)


def _require(name: str) -> str:
    value = os.environ.get(name)
    if value is None or value == "":
        raise ValueError(f"missing required environment variable {name}")
    return value


def load_sealed_document() -> LiveSealedDocument:
    """Load the sealed configuration document from an explicit path or JSON env var."""
    raw_path = os.environ.get("SOC_SERVICE_CONFIG_PATH")
    raw_json = os.environ.get("SOC_SERVICE_CONFIG_JSON")
    if (raw_path is None) == (raw_json is None):
        raise ValueError("supply exactly one of SOC_SERVICE_CONFIG_PATH or SOC_SERVICE_CONFIG_JSON")
    if raw_path is not None:
        payload = Path(raw_path).read_bytes()
    else:
        assert raw_json is not None
        payload = raw_json.encode("utf-8")
    document = LiveSealedDocument.model_validate_json(payload)
    if os.environ.get("SOC_MODE", "live") != "live":
        raise ValueError("SOC_MODE must be live for the live entrypoint")
    return document


def require_region() -> str:
    return _require("AWS_REGION")


def read_secret_bytes(name: str) -> bytes:
    value = _require(name)
    return value.encode("utf-8")


def read_secret_text(name: str) -> str:
    return _require(name)


def site_ca_env_name(environment_id: str) -> str:
    token = environment_id.upper().replace("-", "_")
    return f"SOC_SITE_{token}_CA"


def cursor_keys() -> tuple[dict[str, bytes], str]:
    current_id = _require("SOC_CURSOR_KEY_ID_CURRENT")
    previous_id = _require("SOC_CURSOR_KEY_ID_PREVIOUS")
    keys = {
        current_id: _decode_key_material(_require("SOC_CURSOR_AEAD_CURRENT")),
        previous_id: _decode_key_material(_require("SOC_CURSOR_AEAD_PREVIOUS")),
    }
    return keys, current_id


def receipt_keys() -> tuple[dict[str, bytes], str]:
    current_id = _require("SOC_RECEIPT_KEY_ID_CURRENT")
    previous_id = _require("SOC_RECEIPT_KEY_ID_PREVIOUS")
    keys = {
        current_id: _decode_key_material(_require("SOC_FEEDBACK_RECEIPT_CURRENT")),
        previous_id: _decode_key_material(_require("SOC_FEEDBACK_RECEIPT_PREVIOUS")),
    }
    return keys, current_id


def csrf_secret() -> bytes:
    return _decode_key_material(_require("SOC_CSRF_SECRET"))


def _decode_key_material(value: str) -> bytes:
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("secret material must be valid base64") from exc
    if len(raw) != 32:
        raise ValueError("secret material must decode to exactly 32 bytes")
    return raw


def optional_endpoint(name: str) -> str | None:
    value = os.environ.get(name)
    if value is None or value == "":
        return None
    return value


def assert_no_disallowed_environ(extra_allowed: frozenset[str] = frozenset()) -> None:
    """Guard against accidental ambient configuration in tests."""
    allowed = _ALLOWED_EXACT | extra_allowed
    for key in os.environ:
        if key in allowed:
            continue
        if any(key == prefix or key.startswith(f"{prefix}_") for prefix in _ALLOWED_PREFIXES):
            continue
        if key.startswith("PYTHON") or key in {"PATH", "HOME", "HOSTNAME", "LANG", "LC_ALL"}:
            continue
        raise ValueError(f"unexpected environment variable for live boot: {key}")


def merge_audit_urls(document: LiveSealedDocument) -> LiveSealedDocument:
    """Allow queue URLs to be supplied only through the sealed document."""
    audit = document.audit_queue_url
    feedback = document.feedback_queue_url
    service = document.service.model_copy(
        update={"audit_queue_url": audit},
    )
    return document.model_copy(update={"service": service, "feedback_queue_url": feedback})


def digest_json_mapping(payload: Mapping[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256(encoded).hexdigest()
