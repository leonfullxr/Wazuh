"""Versioned, frozen Wazuh rule-composite qualification."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import cast


class CompositePolicyError(ValueError):
    """A composite policy document is malformed or has invalid provenance."""


@dataclass(frozen=True, slots=True)
class CompositeRulePair:
    base_rule_id: str
    composite_rule_id: str
    same_source_ip: bool


@dataclass(frozen=True, slots=True)
class CompositePolicy:
    wazuh_version: str | None
    policy_id: str | None
    source_path: str | None
    source_sha256: str | None
    pairs: tuple[CompositeRulePair, ...]
    unavailable_reason: str | None = None

    @property
    def available(self) -> bool:
        return self.unavailable_reason is None

    def confirms(self, base_rule_id: str | None, composite_rule_id: str | None) -> bool:
        return self.available and any(
            pair.base_rule_id == base_rule_id
            and pair.composite_rule_id == composite_rule_id
            and pair.same_source_ip
            for pair in self.pairs
        )

    def document(self) -> dict[str, object]:
        """Return the complete versioned policy that belongs in a frozen manifest."""
        if not self.available:
            return {
                "schema_version": 1,
                "wazuh_version": self.wazuh_version,
                "available": False,
                "reason": self.unavailable_reason,
                "policy_id": None,
                "source": None,
                "pairs": [],
            }
        assert self.policy_id is not None
        assert self.source_path is not None
        assert self.source_sha256 is not None
        return {
            "schema_version": 1,
            "wazuh_version": self.wazuh_version,
            "available": True,
            "reason": None,
            "policy_id": self.policy_id,
            "source": {"path": self.source_path, "sha256": self.source_sha256},
            "pairs": [
                {
                    "base_rule_id": pair.base_rule_id,
                    "composite_rule_id": pair.composite_rule_id,
                    "same_source_ip": pair.same_source_ip,
                }
                for pair in self.pairs
            ],
        }

    @classmethod
    def from_document(cls, value: object) -> CompositePolicy:
        """Validate embedded policy evidence without consulting current content files."""
        if not isinstance(value, dict):
            raise CompositePolicyError("frozen composite policy is malformed")
        document = cast(dict[str, object], value)
        if (
            set(document)
            != {
                "schema_version",
                "wazuh_version",
                "available",
                "reason",
                "policy_id",
                "source",
                "pairs",
            }
            or document.get("schema_version") != 1
        ):
            raise CompositePolicyError("frozen composite policy has an unsupported shape")
        version = document.get("wazuh_version")
        if version is not None and (not isinstance(version, str) or not version):
            raise CompositePolicyError("frozen composite policy release is invalid")
        if document.get("available") is False:
            if (
                not isinstance(document.get("reason"), str)
                or document.get("policy_id") is not None
                or document.get("source") is not None
                or document.get("pairs") != []
            ):
                raise CompositePolicyError("unavailable composite policy is malformed")
            return cls(version, None, None, None, (), str(document["reason"]))
        if document.get("available") is not True or document.get("reason") is not None:
            raise CompositePolicyError("frozen composite policy availability is invalid")
        policy_id, source, pairs_value = (
            document.get("policy_id"),
            document.get("source"),
            document.get("pairs"),
        )
        if (
            not isinstance(policy_id, str)
            or not policy_id
            or not isinstance(source, dict)
            or not isinstance(pairs_value, list)
            or not pairs_value
        ):
            raise CompositePolicyError("available composite policy lacks source or pairs")
        source_map = cast(dict[str, object], source)
        if set(source_map) != {"path", "sha256"}:
            raise CompositePolicyError("frozen composite source provenance is malformed")
        source_path, source_sha256 = source_map.get("path"), source_map.get("sha256")
        if (
            not isinstance(source_path, str)
            or not source_path
            or not isinstance(source_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", source_sha256) is None
        ):
            raise CompositePolicyError("frozen composite source provenance is invalid")
        pairs: list[CompositeRulePair] = []
        for raw_pair in cast(list[object], pairs_value):
            if not isinstance(raw_pair, dict):
                raise CompositePolicyError("frozen composite pair is malformed")
            pair = cast(dict[str, object], raw_pair)
            if set(pair) != {"base_rule_id", "composite_rule_id", "same_source_ip"}:
                raise CompositePolicyError("frozen composite pair has an unsupported shape")
            base, composite, same_source = (
                pair.get("base_rule_id"),
                pair.get("composite_rule_id"),
                pair.get("same_source_ip"),
            )
            if (
                not isinstance(base, str)
                or not base.isdecimal()
                or not isinstance(composite, str)
                or not composite.isdecimal()
                or not isinstance(same_source, bool)
            ):
                raise CompositePolicyError("frozen composite pair values are invalid")
            pairs.append(CompositeRulePair(base, composite, same_source))
        if len({(item.base_rule_id, item.composite_rule_id) for item in pairs}) != len(pairs):
            raise CompositePolicyError("frozen composite policy contains duplicate pairs")
        return cls(version, policy_id, source_path, source_sha256, tuple(pairs))

    @property
    def digest(self) -> str:
        canonical = json.dumps(
            self.document(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
        return hashlib.sha256(canonical).hexdigest()


def load_composite_policy(
    wazuh_version: str | None, *, policy_dir: Path | None = None
) -> CompositePolicy:
    """Load only the exact configured release; unknown releases stay unavailable."""
    if not isinstance(wazuh_version, str) or re.fullmatch(r"\d+\.\d+\.\d+", wazuh_version) is None:
        return CompositePolicy(wazuh_version, None, None, None, (), "unsupported_wazuh_release")
    path = (policy_dir or _policy_path()) / f"wazuh-{wazuh_version}.yaml"
    try:
        import yaml

        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return CompositePolicy(wazuh_version, None, None, None, (), "unsupported_wazuh_release")
    except (OSError, UnicodeError) as exc:
        raise CompositePolicyError("composite policy cannot be read") from exc
    except Exception as exc:
        raise CompositePolicyError("composite policy YAML is invalid") from exc
    if not isinstance(loaded, dict):
        raise CompositePolicyError("composite policy has an invalid shape")
    values = cast(dict[str, object], loaded)
    if (
        set(values)
        != {
            "schema_version",
            "policy_id",
            "wazuh_version",
            "source_path",
            "source_sha256",
            "pairs",
        }
        or values.get("schema_version") != 1
        or values.get("wazuh_version") != wazuh_version
    ):
        raise CompositePolicyError("composite policy release or shape is invalid")
    raw_pairs = values.get("pairs")
    if not isinstance(raw_pairs, list):
        raise CompositePolicyError("composite policy pairs are invalid")
    document: dict[str, object] = {
        "schema_version": 1,
        "wazuh_version": wazuh_version,
        "available": True,
        "reason": None,
        "policy_id": values.get("policy_id"),
        "source": {
            "path": values.get("source_path"),
            "sha256": values.get("source_sha256"),
        },
        "pairs": cast(list[object], raw_pairs),
    }
    policy = CompositePolicy.from_document(document)
    if policy.wazuh_version != wazuh_version:
        raise CompositePolicyError("composite policy release differs from its filename")
    return policy


def _policy_path() -> Path:
    return Path(__file__).resolve().parents[4] / "content" / "workspace" / "composites"
