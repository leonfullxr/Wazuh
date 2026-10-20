"""Pure validation for frozen acceptance-to-case traceability."""

from __future__ import annotations

import hashlib
import json
import re
from typing import cast

FIXTURE_VARIANTS = frozenset({"positive", "negative", "boundary", "failure"})
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def case_fixture_bindings(catalog: object) -> dict[str, dict[str, list[str]]]:
    """Return validated case/variant fixture hashes in canonical key order.

    Each variant maps to a non-empty sorted list because an assertion may consume
    more than one independently frozen input. Missing variants mean no accepted
    fixture binding is recorded for that case/variant.
    """
    if not isinstance(catalog, dict):
        raise AssertionError("case catalog must be an object")
    document = cast(dict[str, object], catalog)
    raw_cases = document.get("cases")
    if not isinstance(raw_cases, list):
        raise AssertionError("case catalog cases must be an array")
    cases = cast(list[object], raw_cases)
    result: dict[str, dict[str, list[str]]] = {}
    seen: set[str] = set()
    for raw_case in cases:
        if not isinstance(raw_case, dict):
            raise AssertionError("case catalog entries must be objects")
        row = cast(dict[str, object], raw_case)
        case_id = row.get("case_id")
        if not isinstance(case_id, str) or not case_id:
            raise AssertionError("case catalog case_id must be a non-empty string")
        if case_id in seen:
            raise AssertionError("duplicate case catalog case_id")
        seen.add(case_id)
        if "fixture_sha256_by_variant" not in row:
            continue
        raw_bindings = row["fixture_sha256_by_variant"]
        if not isinstance(raw_bindings, dict) or not raw_bindings:
            raise AssertionError("fixture bindings must be a non-empty object")
        variants = row.get("variants")
        if not isinstance(variants, list):
            raise AssertionError("case variants must be string arrays before fixture binding")
        variant_items = cast(list[object], variants)
        if not all(isinstance(variant, str) for variant in variant_items):
            raise AssertionError("case variants must be string arrays before fixture binding")
        approved_variants = set(cast(list[str], variant_items))
        bindings: dict[str, list[str]] = {}
        for variant, raw_hashes in cast(dict[object, object], raw_bindings).items():
            if not isinstance(variant, str) or variant not in FIXTURE_VARIANTS:
                raise AssertionError("fixture binding has an unknown variant")
            if variant not in approved_variants:
                raise AssertionError("fixture binding references a variant outside the case")
            if not isinstance(raw_hashes, list) or not raw_hashes:
                raise AssertionError("fixture variant hashes must be non-empty arrays")
            hashes = cast(list[object], raw_hashes)
            if not all(isinstance(item, str) and _SHA256_RE.fullmatch(item) for item in hashes):
                raise AssertionError("fixture hashes must be lower-case SHA-256 hex strings")
            values = cast(list[str], hashes)
            if values != sorted(set(values)):
                raise AssertionError("fixture hashes must be sorted and unique")
            bindings[variant] = values
        result[case_id] = {variant: bindings[variant] for variant in sorted(bindings)}
    return {case_id: result[case_id] for case_id in sorted(result)}


def case_fixture_bindings_sha256(catalog: object) -> str:
    bindings = case_fixture_bindings(catalog)
    return hashlib.sha256(canonical_json(bindings)).hexdigest()


def validate_case_fixture_bindings(catalog: object, expected_sha256: object) -> None:
    if not isinstance(expected_sha256, str) or not _SHA256_RE.fullmatch(expected_sha256):
        raise AssertionError("case fixture binding digest must be lower-case SHA-256")
    if case_fixture_bindings_sha256(catalog) != expected_sha256:
        raise AssertionError("case fixture bindings differ from frozen digest")


def validate_traceability(
    traceability: object,
    expected_acceptance_ids: set[str],
    known_case_ids: set[str],
    known_task_ids: set[str],
) -> None:
    if not isinstance(traceability, dict):
        raise AssertionError("traceability must be an object")
    document = cast(dict[str, object], traceability)
    raw_entries = document.get("entries")
    if not isinstance(raw_entries, list):
        raise AssertionError("traceability entries must be an array")
    entries = cast(list[object], raw_entries)
    if not all(isinstance(entry, dict) for entry in entries):
        raise AssertionError("traceability entries must be objects")
    rows = cast(list[dict[str, object]], entries)
    acceptance_ids: list[str] = []
    for row in rows:
        acceptance_id = row.get("acceptance_id")
        if not isinstance(acceptance_id, str):
            raise AssertionError("traceability acceptance_id must be a string")
        acceptance_ids.append(acceptance_id)
    if len(acceptance_ids) != len(set(acceptance_ids)):
        raise AssertionError("duplicate traceability acceptance_id")
    if set(acceptance_ids) != expected_acceptance_ids:
        raise AssertionError("traceability acceptance inventory differs from the frozen inventory")

    required_variants = {"positive", "negative", "boundary", "failure"}
    for row in rows:
        tasks = row.get("tasks")
        test_node_ids = row.get("test_node_ids")
        results_status = row.get("results_status")
        review_cases = row.get("review_cases")
        variants = row.get("required_variants")
        if not isinstance(tasks, list) or not tasks:
            raise AssertionError("traceability task references must be non-empty strings")
        task_values = cast(list[object], tasks)
        if not all(isinstance(task, str) for task in task_values):
            raise AssertionError("traceability task references must be non-empty strings")
        if not set(cast(list[str], task_values)) <= known_task_ids:
            raise AssertionError("traceability references an unknown task")
        if not isinstance(test_node_ids, list) or test_node_ids:
            raise AssertionError("traceability must not claim uncollected test nodes")
        if results_status != "PENDING_IMPLEMENTATION":
            raise AssertionError("traceability must retain pending implementation status")
        if not isinstance(review_cases, list):
            raise AssertionError("traceability review_cases must be string arrays")
        case_values = cast(list[object], review_cases)
        if not all(isinstance(case_id, str) for case_id in case_values):
            raise AssertionError("traceability review_cases must be string arrays")
        if not set(cast(list[str], case_values)) <= known_case_ids:
            raise AssertionError("traceability references an unknown review case")
        if not isinstance(variants, list):
            raise AssertionError("traceability required_variants must be string arrays")
        variant_values = cast(list[object], variants)
        if not all(isinstance(variant, str) for variant in variant_values):
            raise AssertionError("traceability required_variants must be string arrays")
        if set(cast(list[str], variant_values)) != required_variants:
            raise AssertionError("traceability required_variants differ from the frozen variants")
