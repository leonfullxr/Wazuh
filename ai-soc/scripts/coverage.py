#!/usr/bin/env python3
"""Join actual JUnit nodes to frozen requirements, variants and case registry."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import cast

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "build/evidence"
VARIANTS = {"positive", "negative", "boundary", "failure"}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
CI_RESULT_FILES = (
    "contract.xml",
    "unit.xml",
    "security.xml",
    "golden.xml",
    "admission-runtime.xml",
    "e2e.xml",
    "routes.xml",
    "ui.xml",
    "reproducibility.xml",
)


@dataclass(frozen=True, slots=True)
class CaseScope:
    requirements: frozenset[str]
    variants: frozenset[str]
    fixture_hashes: dict[str, frozenset[str]]


COMPONENT_ONLY_NODE_PREFIXES = {
    "QA-012.resolution": ("tests.unit.api.test_app.",),
    "SEC-001.resolution": ("tests.unit.feedback.test_receipts.", "tests.unit.feedback.test_sqs."),
}


def _object(path: Path) -> dict[str, object]:
    parsed: object = json.loads(path.read_text())
    if not isinstance(parsed, dict):
        raise ValueError(f"expected JSON object in {path.relative_to(ROOT)}")
    value = cast(dict[object, object], parsed)
    if not all(isinstance(key, str) for key in value):
        raise ValueError(f"expected string object keys in {path.relative_to(ROOT)}")
    return cast(dict[str, object], value)


def _strings(value: object, *, source: str, field: str) -> set[str]:
    if not isinstance(value, list):
        raise ValueError(f"expected {field} list in {source}")
    values = cast(list[object], value)
    if not all(isinstance(item, str) for item in values):
        raise ValueError(f"expected string {field} values in {source}")
    return set(cast(list[str], values))


def _add_scope(
    scopes: dict[str, CaseScope],
    *,
    case_id: str,
    requirements: set[str],
    variants: set[str],
    fixture_hashes: dict[str, set[str]] | None = None,
) -> None:
    prior = scopes.get(case_id)
    hashes = {variant: set(values) for variant, values in (fixture_hashes or {}).items()}
    if prior is not None:
        for variant, values in prior.fixture_hashes.items():
            hashes.setdefault(variant, set()).update(values)
        requirements.update(prior.requirements)
        variants.update(prior.variants)
    scopes[case_id] = CaseScope(
        frozenset(requirements),
        frozenset(variants),
        {variant: frozenset(values) for variant, values in hashes.items()},
    )


def _registry() -> tuple[set[str], dict[str, CaseScope]]:
    freeze = _object(ROOT / "contracts/v1/freeze.json")
    catalog = _object(ROOT / "docs/case_catalog.json")
    formal = _object(ROOT / "docs/golden_examples.json")
    acceptance_ids = freeze.get("acceptance_ids")
    if not isinstance(acceptance_ids, list) or not all(
        isinstance(value, str) for value in cast(list[object], acceptance_ids)
    ):
        raise ValueError("invalid acceptance_ids in frozen contract")
    scopes: dict[str, CaseScope] = {}
    canonical_bindings: dict[str, dict[str, list[str]]] = {}
    catalog_case_ids: set[str] = set()
    catalog_cases = catalog.get("cases")
    if not isinstance(catalog_cases, list):
        raise ValueError("expected cases list in docs/case_catalog.json")
    for raw in cast(list[object], catalog_cases):
        entry = _object_value(raw, "case catalog row")
        case_id = entry.get("case_id")
        if not isinstance(case_id, str) or not case_id:
            raise ValueError("case catalog row has no case_id")
        if case_id in catalog_case_ids:
            raise ValueError(f"duplicate case catalog ID: {case_id}")
        catalog_case_ids.add(case_id)
        requirements = _strings(
            entry.get("requirements"), source="docs/case_catalog.json", field="requirements"
        )
        variants = _strings(
            entry.get("variants"), source="docs/case_catalog.json", field="variants"
        )
        catalog_hashes: dict[str, set[str]] = {}
        if "fixture_sha256_by_variant" in entry:
            raw_bindings = _object_value(
                entry.get("fixture_sha256_by_variant"),
                f"fixture bindings for {case_id}",
            )
            if not raw_bindings:
                raise ValueError(f"fixture bindings must be nonempty for {case_id}")
            for raw_variant, raw_hashes in raw_bindings.items():
                if raw_variant not in VARIANTS or raw_variant not in variants:
                    raise ValueError(f"fixture binding variant is outside catalog scope: {case_id}")
                hashes = _strings(
                    raw_hashes,
                    source=f"docs/case_catalog.json ({case_id}/{raw_variant})",
                    field="fixture hashes",
                )
                if not hashes or any(not SHA256.fullmatch(value) for value in hashes):
                    raise ValueError(f"invalid fixture hash binding: {case_id} ({raw_variant})")
                raw_hash_list = cast(list[str], raw_hashes)
                if raw_hash_list != sorted(set(raw_hash_list)):
                    raise ValueError(f"fixture hash binding must be sorted and unique: {case_id}")
                catalog_hashes[raw_variant] = hashes
            canonical_bindings[case_id] = {
                variant: sorted(hashes) for variant, hashes in catalog_hashes.items()
            }
        _add_scope(
            scopes,
            case_id=case_id,
            requirements=requirements,
            variants=variants,
            fixture_hashes=catalog_hashes,
        )

    binding_bytes = json.dumps(
        canonical_bindings,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    frozen_binding_digest = freeze.get("case_fixture_bindings_sha256")
    if not isinstance(frozen_binding_digest, str) or hashlib.sha256(binding_bytes).hexdigest() != (
        frozen_binding_digest
    ):
        raise ValueError("case catalog fixture bindings differ from the accepted frozen digest")

    formal_cases = formal.get("cases")
    if not isinstance(formal_cases, list):
        raise ValueError("expected cases list in docs/golden_examples.json")
    for raw in cast(list[object], formal_cases):
        entry = _object_value(raw, "formal golden row")
        case_id, variant, fixture_hash = (
            entry.get("case_id"),
            entry.get("variant"),
            entry.get("fixture_sha256"),
        )
        if not isinstance(case_id, str) or not isinstance(variant, str):
            raise ValueError("formal golden row needs case_id and variant")
        if not isinstance(fixture_hash, str) or not SHA256.fullmatch(fixture_hash):
            raise ValueError(f"formal golden row has invalid fixture hash: {case_id}")
        _add_scope(
            scopes,
            case_id=case_id,
            requirements=_strings(
                entry.get("requirements"), source="docs/golden_examples.json", field="requirements"
            ),
            variants={variant},
            fixture_hashes={variant: {fixture_hash}},
        )

    contract_cases = _object(ROOT / "tests/fixtures/v1/contract_cases.json").get("cases")
    if not isinstance(contract_cases, list):
        raise ValueError("expected cases list in tests/fixtures/v1/contract_cases.json")
    for raw in cast(list[object], contract_cases):
        entry = _object_value(raw, "contract fixture row")
        case_id, variant, fixture_hash = (
            entry.get("case_id"),
            entry.get("variant"),
            entry.get("fixture_sha256"),
        )
        if not isinstance(case_id, str) or not isinstance(variant, str):
            raise ValueError("contract fixture row needs case_id and variant")
        if not isinstance(fixture_hash, str) or not SHA256.fullmatch(fixture_hash):
            raise ValueError(f"contract fixture row has invalid fixture hash: {case_id}")
        _add_scope(
            scopes,
            case_id=case_id,
            requirements=_strings(
                entry.get("requirements"),
                source="tests/fixtures/v1/contract_cases.json",
                field="requirements",
            ),
            variants={variant},
            fixture_hashes={variant: {fixture_hash}},
        )

    return set(cast(list[str], acceptance_ids)), scopes


def _object_value(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"expected object in {label}")
    raw = cast(dict[object, object], value)
    if not all(isinstance(key, str) for key in raw):
        raise ValueError(f"expected string keys in {label}")
    return cast(dict[str, object], raw)


def _properties(case: ET.Element) -> dict[str, str]:
    node = case.find("properties")
    if node is None:
        return {}
    result: dict[str, str] = {}
    for prop in node.findall("property"):
        name, value = prop.get("name"), prop.get("value")
        if name and value is not None:
            result[name] = value
    return result


def resolve_results_dir(path: Path) -> Path:
    resolved = (path if path.is_absolute() else ROOT / path).resolve()
    try:
        resolved.relative_to(ROOT)
    except ValueError as exc:
        raise ValueError("coverage results must stay inside the repository") from exc
    return resolved


def collect(
    results: Path,
    *,
    expected_files: tuple[str, ...] | None = None,
) -> dict[str, object]:
    results = resolve_results_dir(results)
    requirement_ids, case_scopes = _registry()
    observed: dict[str, set[str]] = defaultdict(set)
    collected_nodes: list[dict[str, object]] = []
    failures: list[str] = []
    seen_node_ids: set[str] = set()
    seen_case_variants: set[tuple[str, str, str]] = set()
    if expected_files is None:
        xml_files = sorted(results.glob("*.xml"))
    else:
        if len(set(expected_files)) != len(expected_files):
            raise ValueError("expected JUnit result names must be unique")
        xml_files = [results / name for name in expected_files if (results / name).is_file()]
        missing_files = sorted(set(expected_files) - {path.name for path in xml_files})
        failures.extend(f"missing expected JUnit result file: {name}" for name in missing_files)
    if not xml_files:
        failures.append("no JUnit result files found")
    for path in xml_files:
        root = ET.parse(path).getroot()
        testcases = root.findall(".//testcase")
        if not testcases:
            failures.append(f"zero tests collected in {path.relative_to(ROOT)}")
        for case in testcases:
            props = _properties(case)
            node_id = ".".join(filter(None, (case.get("classname"), case.get("name"))))
            skipped = case.find("skipped") is not None
            failed = case.find("failure") is not None or case.find("error") is not None
            requirements = [value for value in props.get("acceptance_ids", "").split(",") if value]
            case_id = props.get("case_id", "")
            variant = props.get("variant", "")
            fixture_hash = props.get("fixture_sha256", "")
            if node_id in seen_node_ids:
                failures.append(f"duplicate collected node ID: {node_id}")
            seen_node_ids.add(node_id)
            valid = not skipped and not failed and bool(node_id)
            if skipped:
                failures.append(f"skipped test node: {node_id}")
            if failed:
                failures.append(f"failed test node: {node_id}")
            unknown = set(requirements) - requirement_ids
            scope_valid = not unknown
            if unknown:
                failures.append(f"unknown acceptance IDs for {node_id}: {sorted(unknown)}")
            if requirements and not (case_id and variant and fixture_hash):
                failures.append(f"requirements lack case/variant/fixture metadata for {node_id}")
                scope_valid = False
            if case_id or variant or fixture_hash:
                if not case_id:
                    failures.append(f"metadata lacks independent case ID for {node_id}")
                    scope_valid = False
                else:
                    scope = case_scopes.get(case_id)
                    if scope is None:
                        failures.append(f"unregistered case ID for {node_id}: {case_id}")
                        scope_valid = False
                    elif variant not in scope.variants:
                        failures.append(
                            f"out-of-scope variant for {node_id}: {case_id} ({variant})"
                        )
                        scope_valid = False
                    if variant not in VARIANTS:
                        failures.append(f"invalid/missing variant for {node_id}: {case_id}")
                        scope_valid = False
                    if scope is not None:
                        out_of_scope = set(requirements) - scope.requirements
                        if out_of_scope:
                            failures.append(
                                f"out-of-scope acceptance IDs for {node_id} ({case_id}): "
                                f"{sorted(out_of_scope)}"
                            )
                            scope_valid = False
                        fixture_scope = scope.fixture_hashes.get(variant)
                        if requirements and fixture_scope is None:
                            failures.append(
                                f"no authoritative fixture SHA-256 in frozen registry for "
                                f"{node_id}: {case_id} ({variant})"
                            )
                            scope_valid = False
                        elif fixture_scope is not None and fixture_hash not in fixture_scope:
                            failures.append(
                                f"fixture SHA-256 outside registered scope for {node_id}: "
                                f"{case_id} ({variant})"
                            )
                            scope_valid = False
                    for forbidden_prefix in COMPONENT_ONLY_NODE_PREFIXES.get(case_id, ()):
                        if node_id.startswith(forbidden_prefix):
                            failures.append(
                                f"component-only node credited to composed case for {node_id}: "
                                f"{case_id}"
                            )
                            scope_valid = False
                    if not SHA256.fullmatch(fixture_hash):
                        failures.append(f"missing/invalid fixture SHA-256 for {node_id}: {case_id}")
                        scope_valid = False
                    case_variant = (path.name, case_id, variant)
                    if case_variant in seen_case_variants:
                        failures.append(
                            f"duplicate case/variant result in {path.name}: {case_id} ({variant})"
                        )
                    seen_case_variants.add(case_variant)
            if valid and scope_valid:
                for requirement in requirements:
                    if requirement in requirement_ids:
                        observed[requirement].add(variant)
            collected_nodes.append(
                {
                    "node_id": node_id,
                    "result_file": path.name,
                    "outcome": "skipped" if skipped else "failed" if failed else "passed",
                    "case_id": case_id or None,
                    "variant": variant or None,
                    "fixture_sha256": fixture_hash or None,
                    "acceptance_ids": requirements,
                }
            )

    traceability = _object(ROOT / "docs/traceability.json").get("entries")
    if not isinstance(traceability, list):
        raise ValueError("invalid entries in docs/traceability.json")
    required: dict[str, set[str]] = {}
    for raw in cast(list[object], traceability):
        if not isinstance(raw, dict):
            raise ValueError("invalid traceability entry")
        entry = cast(dict[str, object], raw)
        acceptance_id, variants = entry.get("acceptance_id"), entry.get("required_variants")
        if not isinstance(acceptance_id, str) or not isinstance(variants, list):
            raise ValueError("invalid traceability requirement/variants")
        variant_values = cast(list[object], variants)
        if not all(isinstance(value, str) and value in VARIANTS for value in variant_values):
            raise ValueError(f"invalid variants for {acceptance_id}")
        required[acceptance_id] = set(cast(list[str], variant_values))

    rows: list[dict[str, object]] = []
    missing: list[dict[str, object]] = []
    for acceptance_id in sorted(requirement_ids):
        need = required.get(acceptance_id, VARIANTS)
        have = observed.get(acceptance_id, set())
        complete = need <= have
        rows.append(
            {
                "acceptance_id": acceptance_id,
                "required_variants": sorted(need),
                "passed_variants": sorted(have),
                "coverage_percent": round(100 * len(have & need) / len(need), 2),
                "complete": complete,
            }
        )
        if not complete:
            missing.append({"acceptance_id": acceptance_id, "variants": sorted(need - have)})
    passed_count = sum(node["outcome"] == "passed" for node in collected_nodes)
    skipped_count = sum(node["outcome"] == "skipped" for node in collected_nodes)
    failed_count = sum(node["outcome"] == "failed" for node in collected_nodes)
    complete_count = sum(row["complete"] is True for row in rows)
    return {
        "schema_version": "1",
        "result_files": [str(path.relative_to(ROOT)) for path in xml_files],
        "collected_node_count": len(collected_nodes),
        "passed_node_count": passed_count,
        "skipped_node_count": skipped_count,
        "failed_node_count": failed_count,
        "requirements": rows,
        "requirement_coverage_percent": round(100 * complete_count / len(rows), 2) if rows else 0,
        "nodes": collected_nodes,
        "missing": missing,
        "failures": failures,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--require-all", action="store_true")
    parser.add_argument("--results", type=Path, default=RESULTS)
    args = parser.parse_args()
    results = resolve_results_dir(args.results)
    report = collect(results, expected_files=CI_RESULT_FILES)
    results.mkdir(parents=True, exist_ok=True)
    out = results / "coverage.json"
    out.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(
        f"collected={report['collected_node_count']} "
        f"requirement_coverage={report['requirement_coverage_percent']}%"
    )
    failures = cast(list[str], report["failures"])
    missing = cast(list[dict[str, object]], report["missing"])
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
    failed_nodes = report["failed_node_count"]
    skipped_nodes = report["skipped_node_count"]
    if args.require_all and (missing or failures or failed_nodes or skipped_nodes):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
