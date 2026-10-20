"""Read-only access to the canonical fixture bindings for case metadata."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import cast

import pytest

ROOT = Path(__file__).resolve().parents[3]
CATALOG_PATH = ROOT / "docs" / "case_catalog.json"


def canonical_fixture_sha256(case_id: str, variant: str) -> str:
    catalog: object = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    if not isinstance(catalog, dict) or not isinstance(catalog.get("cases"), list):
        raise AssertionError("case catalog is not a case array")
    cases = cast(list[object], catalog["cases"])
    for raw_case in cases:
        if not isinstance(raw_case, dict):
            raise AssertionError("case catalog entry is not an object")
        case = cast(dict[str, object], raw_case)
        if case.get("case_id") != case_id:
            continue
        bindings = case.get("fixture_sha256_by_variant")
        if not isinstance(bindings, dict):
            raise AssertionError(f"No fixture binding for {case_id}")
        raw_hashes = cast(dict[object, object], bindings).get(variant)
        if not isinstance(raw_hashes, list) or len(raw_hashes) != 1:
            raise AssertionError(f"Binding for {case_id}/{variant} must contain one fixture")
        digest = raw_hashes[0]
        if not isinstance(digest, str) or len(digest) != 64:
            raise AssertionError(f"Binding for {case_id}/{variant} is invalid")
        return digest
    raise AssertionError(f"case catalog does not register {case_id}")


def canonical_acceptance_ids(case_id: str) -> tuple[str, ...]:
    catalog: object = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    if not isinstance(catalog, dict) or not isinstance(catalog.get("cases"), list):
        raise AssertionError("case catalog is not a case array")
    for raw_case in cast(list[object], catalog["cases"]):
        if not isinstance(raw_case, dict):
            raise AssertionError("case catalog entry is not an object")
        case = cast(dict[str, object], raw_case)
        if case.get("case_id") == case_id:
            requirements = case.get("requirements")
            if (
                not isinstance(requirements, list)
                or not requirements
                or not all(isinstance(value, str) for value in requirements)
            ):
                raise AssertionError(f"Case {case_id} has no accepted requirements")
            return tuple(cast(list[str], requirements))
    raise AssertionError(f"case catalog does not register {case_id}")


def assert_fixture_matches_all_variants(case_id: str, path: Path) -> str:
    expected = {
        canonical_fixture_sha256(case_id, variant)
        for variant in ("positive", "negative", "boundary", "failure")
    }
    if len(expected) != 1:
        raise AssertionError(f"{case_id} uses variant-specific fixtures; assert a single variant")
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual not in expected:
        raise AssertionError(f"{case_id} fixture differs from the canonical binding")
    return actual


def registered_case_variants(case_id: str) -> tuple[object, ...]:
    return tuple(
        pytest.param(
            variant,
            id=variant,
            marks=(
                pytest.mark.acceptance(*canonical_acceptance_ids(case_id)),
                pytest.mark.case_id(case_id),
                pytest.mark.variant(variant),
                pytest.mark.fixture_sha256(canonical_fixture_sha256(case_id, variant)),
            ),
        )
        for variant in ("positive", "negative", "boundary", "failure")
    )
