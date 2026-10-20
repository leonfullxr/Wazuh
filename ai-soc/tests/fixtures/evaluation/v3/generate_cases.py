"""Generate synthetic replay v3 fixtures from frozen v2 source records."""

# ruff: noqa: E501

from __future__ import annotations

import copy
import hashlib
import json
import shutil
from datetime import UTC
from pathlib import Path

ROOT = Path(__file__).resolve().parent
V2 = ROOT.parent / "v2"
AS_OF = "2026-10-17T12:00:00.000000Z"


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def sha(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + "\n", encoding="ascii"
    )


def stamp(seconds_ago: int) -> str:
    from datetime import datetime, timedelta

    return (
        (datetime(2026, 10, 17, 12, tzinfo=UTC) - timedelta(seconds=seconds_ago))
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def source(case_id: str, source_case: str = "source_auth_10") -> dict:
    item = json.loads((V2 / "cases" / f"{source_case}.json").read_text())
    item["case_id"] = case_id
    return item


def search_response(item: dict) -> dict:
    return next(r["response"] for r in item["responses"] if r["path"] == "/_search")


def update_timestamp(item: dict, ages: list[int | str | None]) -> None:
    response = search_response(item)
    hits = response["hits"]["hits"]
    if not ages:
        return
    if len(ages) > len(hits):
        original = copy.deepcopy(hits[0])
        for j in range(len(ages) - len(hits)):
            extra = copy.deepcopy(original)
            extra["_id"] = f"{item['case_id']}-extra-{j}"
            extra["sort"][2] = extra["_id"]
            hits.append(extra)
    for i, hit in enumerate(hits):
        value = ages[min(i, len(ages) - 1)]
        if value is None:
            hit["_source"].pop("@timestamp", None)
        elif isinstance(value, int):
            hit["_source"]["@timestamp"] = stamp(value)
            from datetime import datetime

            epoch = int(
                datetime.fromisoformat(stamp(value).replace("Z", "+00:00")).timestamp() * 1000
            )
            hit["sort"][0] = epoch
        else:
            hit["_source"]["@timestamp"] = value


def expected_source(
    checks: dict[str, str],
    *,
    count: dict | None = None,
    rows: list[dict] | None = None,
    explanations: dict | None = None,
) -> dict:
    result = {
        "checks": checks,
        "count": {"auth_rows": count or {"approximate": False, "relation": "eq", "value": 10}},
        "fetch": {"auth_rows": "rows"},
        "row_cardinality": {"auth_rows": len(rows) if rows is not None else 2},
        "visibility": {"auth_rows": "full"},
        "language": "en",
        "abstention": {"auth_rows": False},
    }
    if rows is not None:
        result["rows"] = {"auth_rows": rows}
    if explanations is not None:
        result["check_explanations"] = explanations
    return result


def add_recency(pack: dict, outcome: str) -> None:
    eid = "ev1_" + hashlib.sha256((pack["question_id"] + "|auth_recency").encode()).hexdigest()
    pack["checks"].append(
        {
            "check_id": "auth_recency",
            "evidence_ids": [eid],
            "expectation_id": None,
            "label": "auth_recency",
            "message": "Newest valid returned timestamp is outside the configured synthetic limit; based on returned rows only.",
            "outcome": outcome,
            "topic_id": "auth_review",
        }
    )
    source_item = next(x for x in pack["items"] if x["kind"] == "check")
    item = copy.deepcopy(source_item)
    item.update(
        {
            "check_id": "auth_recency",
            "evidence_id": eid,
            "source": {"operand_ids": [], "step_id": "auth_recency_step"},
            "values": {"outcome": outcome},
        }
    )
    pack["items"].append(item)
    pack["sha256"] = sha({k: v for k, v in pack.items() if k != "sha256"})


def main() -> None:
    (ROOT / "cases").mkdir(parents=True, exist_ok=True)
    (ROOT / "catalog").mkdir(parents=True, exist_ok=True)
    for p in (V2 / "cases").glob("*.json"):
        shutil.copyfile(p, ROOT / "cases" / p.name)
    for p in (V2 / "catalog").rglob("*.json"):
        target = ROOT / "catalog" / p.relative_to(V2 / "catalog")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(p, target)

    playbook_path = ROOT / "catalog/playbooks/auth_review.json"
    playbook = json.loads(playbook_path.read_text())
    playbook["internal_context"] += (
        " The recency limit of 3600 s is synthetic; real limits are deployment inputs."
    )
    playbook["steps"].append(
        {
            "kind": "record_age",
            "step_id": "auth_recency_step",
            "check_id": "auth_recency",
            "fetch_id": "auth_rows",
            "max_age_seconds": 3600,
            "label": {
                "en": "Newest returned record within synthetic limit",
                "es": "Registro devuelto reciente dentro del umbral sint\u00e9tico",
            },
        }
    )
    write(playbook_path, playbook)
    topic_path = ROOT / "catalog/topics/auth_review.json"
    topic = json.loads(topic_path.read_text())
    topic["finding_template_ids"].append("auth_recency_gap")
    write(topic_path, topic)
    template = {
        "template_id": "auth_recency_gap",
        "topic_id": "auth_review",
        "kind": "observation",
        "texts": {
            "en": "The newest returned record with a valid timestamp inside the read window is older than the configured synthetic limit; visible data may be delayed, filtered or incomplete; confirm ingestion manually. Outcome {o}.",
            "es": "El registro devuelto m\u00e1s reciente con una marca de tiempo v\u00e1lida dentro de la ventana de lectura supera el l\u00edmite de antig\u00fcedad sint\u00e9tico configurado; los datos visibles pueden estar retrasados, filtrados o incompletos; confirme la ingesta manualmente. Resultado {o}.",
        },
        "required_bindings": {"o": ["outcome"]},
        "required_check_outcomes": [{"check_id": "auth_recency", "outcome": "failed"}],
        "allowed_evidence_kinds": ["check"],
        "relations": [],
    }
    write(ROOT / "catalog/finding-templates/auth_recency_gap.json", template)

    src_specs = [
        ("source_age_3599", [3599, 4000], "passed", 0),
        ("source_age_3600", [3600, 4000], "passed", 0),
        ("source_age_3601", [3601, 4000], "failed", 0),
        ("source_newest_second", [5000, 1200], "passed", 0),
        (
            "source_invalid_neighbors",
            [
                1200,
                None,
                "bad-time",
                "2026-10-17T11:50:00",
                "2026-10-17T12:00:00.000Z",
            ],
            "passed",
            4,
        ),
        ("source_invalid_only", [None, "not-a-time"], "unknown", 2),
        ("source_zero", [], "unknown", 0),
        ("source_approx_fresh", [30, 4000], "passed", 0),
        ("source_first_page_fresh", [30, 4000], "passed", 0),
        ("source_stale_large_total", [9000, 10000], "failed", 0),
        ("source_age_3601_es", [3601, 4000], "failed", 0),
    ]
    src_manifest = []
    labels = []
    for n, (case_id, ages, outcome, invalid) in enumerate(src_specs):
        item = source(case_id)
        update_timestamp(item, ages)
        response = search_response(item)
        if not ages:
            response["hits"]["hits"] = []
            response["hits"]["total"] = {"relation": "eq", "value": 0}
        if case_id == "source_zero":
            item["responses"].extend(
                [
                    {
                        "method": "GET",
                        "path": "/_resolve/index/wazuh-alerts-*",
                        "body_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
                        "status": 200,
                        "response": {"indices": [{"name": "wazuh-alerts-2026.10.17"}]},
                    },
                    *[
                        {
                            "method": "POST",
                            "path": "/_search",
                            "body_sha256": digest,
                            "status": 200,
                            "response": {
                                "hits": {"hits": [], "total": {"relation": "eq", "value": 0}},
                                "timed_out": False,
                                "took": 1,
                            },
                        }
                        for digest in (
                            "7c2a7f191489af4ac44e2973533340406dd6e84cb113aa4b730fe240fa2cfe19",
                            "a0228116855c6fdd322da9a9bebcf24ac6d7bb7d4eb66dcfd1fa134a164e9ba6",
                            "a0228116855c6fdd322da9a9bebcf24ac6d7bb7d4eb66dcfd1fa134a164e9ba6",
                        )
                    ],
                ]
            )
        if case_id == "source_approx_fresh":
            response["hits"]["total"] = {"relation": "gte", "value": 10}
        if case_id == "source_first_page_fresh":
            item["site"]["pit_supported"] = False
            item["responses"] = [r for r in item["responses"] if "point_in_time" not in r["path"]]
            search = next(r for r in item["responses"] if r["path"] == "/_search")
            search["path"] = "/wazuh-alerts-*/_search"
            search["body_sha256"] = (
                "58e8dfe50d0903b6efefac9c79e96677c5e6a11740af06383c2591944fe2991b"
            )
        if case_id == "source_stale_large_total":
            response["hits"]["total"] = {"relation": "eq", "value": 5000}
        if case_id in {"source_invalid_only", "source_zero"}:
            for r in item["responses"]:
                if r["path"] == "/_search" and not ages:
                    r["response"]["hits"]["hits"] = []
        if case_id == "source_age_3601_es":
            item["question"] = "Investiga la revisión de autenticación."
        rowcount = len(response["hits"]["hits"])
        item["principal"]["sub"] = f"synthetic-analyst-{n + 20:02d}"
        write(ROOT / "cases" / f"{case_id}.json", item)
        if case_id == "source_approx_fresh":
            other_checks = {
                "auth_nonzero": "unknown",
                "auth_volume": "unknown",
                "auth_sources": "passed",
                "auth_priority": "failed",
            }
        elif case_id == "source_zero":
            other_checks = {
                "auth_nonzero": "failed",
                "auth_volume": "failed",
                "auth_sources": "unknown",
                "auth_priority": "unknown",
            }
        elif case_id == "source_invalid_only":
            other_checks = {
                "auth_nonzero": "passed",
                "auth_volume": "passed",
                "auth_sources": "passed",
                "auth_priority": "failed",
            }
        else:
            other_checks = {
                "auth_nonzero": "passed" if rowcount else "failed",
                "auth_volume": "passed" if response["hits"]["total"]["value"] >= 10 else "failed",
                "auth_sources": "passed",
                "auth_priority": "failed",
            }
        checks = {**other_checks, "auth_recency": outcome}
        projected = []
        for hit in response["hits"]["hits"]:
            raw = hit.get("_source", {})
            projected.append(
                {
                    "agent.id": raw.get("agent", {}).get("id"),
                    "data.srcip": raw.get("data", {}).get("srcip"),
                    "rule.id": raw.get("rule", {}).get("id"),
                    "rule.level": raw.get("rule", {}).get("level"),
                    "timestamp": raw.get("@timestamp"),
                }
            )
        exp = expected_source(
            checks,
            count={
                "approximate": response["hits"]["total"]["relation"] == "gte",
                "relation": response["hits"]["total"]["relation"],
                "value": response["hits"]["total"]["value"],
            },
            rows=projected,
            explanations={
                "auth_recency": {
                    "invalid_timestamp_rows": invalid,
                    "returned_rows_only": True,
                    "approximate_total_noted": response["hits"]["total"]["relation"] == "gte",
                    "first_page_only": case_id == "source_first_page_fresh",
                }
            },
        )
        exp["language"] = "es" if case_id.endswith("_es") else "en"
        labels.append(
            {
                "case_id": case_id,
                "authored_at": "2026-10-20",
                "reviewer": "synthetic-label-author",
                "outcome": "unresolved",
                "sensor_detected": False,
                "rationale": f"Executor anchor is {AS_OF}; newest valid timestamp age and invalid-row count determine auth_recency. Other outcomes follow the frozen auth_review checks.",
                "expected_observations": exp,
                "required_findings": [],
                "permitted_findings": [],
            }
        )
        src_manifest.append(
            {
                "case_id": case_id,
                "stage": "source",
                "language": "es" if case_id.endswith("_es") else "en",
                "topic_id": "auth_review",
                "partition": "holdout",
                "incident_id": f"soc007-src-{n:03d}",
                "dedup_key": "family-source-auth-age-boundary"
                if case_id
                in {"source_age_3599", "source_age_3600", "source_age_3601", "source_age_3601_es"}
                else f"dedup-{case_id}",
                "entity_keys": sorted(
                    {
                        value
                        for hit in response["hits"]["hits"]
                        for value in (
                            hit.get("_source", {}).get("agent", {}).get("id"),
                            hit.get("_source", {}).get("data", {}).get("srcip"),
                        )
                        if isinstance(value, str)
                    }
                ),
                "input_path": f"cases/{case_id}.json",
                "as_of": AS_OF,
                "question": item["question"],
            }
        )

    for case_id, source_case, outcome, status in [
        ("source_denied_recency", "source_denied", "denied", 403),
        ("source_unavailable", "source_auth_10", "unknown", 500),
    ]:
        item = source(case_id, source_case)
        for r in item["responses"]:
            if r["path"] == "/_search":
                r["status"] = status
                if status == 500:
                    r["response"] = {"error": {"type": "synthetic_unavailable"}}
        write(ROOT / "cases" / f"{case_id}.json", item)
        label = "denied" if outcome == "denied" else "unknown"
        checks = {
            "auth_nonzero": label,
            "auth_volume": label,
            "auth_sources": label,
            "auth_priority": label,
            "auth_recency": outcome,
        }
        labels.append(
            {
                "case_id": case_id,
                "authored_at": "2026-10-20",
                "reviewer": "synthetic-label-author",
                "outcome": "unresolved",
                "sensor_detected": False,
                "rationale": "The frozen backend status determines denied or unavailable precedence for all checks.",
                "expected_observations": {
                    "checks": checks,
                    "count": {"auth_rows": {"state": "unknown"}},
                    "fetch": {"auth_rows": "denied" if status == 403 else "unavailable"},
                    "row_cardinality": {"auth_rows": 0},
                    "rows": {"auth_rows": []},
                    "visibility": {"auth_rows": "full"},
                    "abstention": {"auth_rows": True},
                    "check_explanations": {
                        "auth_recency": {
                            "returned_rows_only": True,
                            "invalid_timestamp_rows": 0,
                            "approximate_total_noted": False,
                            "first_page_only": False,
                        }
                    },
                },
                "required_findings": [],
                "permitted_findings": [],
            }
        )
        src_manifest.append(
            {
                "case_id": case_id,
                "stage": "source",
                "language": "en",
                "topic_id": "auth_review",
                "partition": "holdout",
                "incident_id": f"soc007-src-{len(src_manifest):03d}",
                "dedup_key": f"dedup-{case_id}",
                "entity_keys": ["302", "192.0.2.41"],
                "input_path": f"cases/{case_id}.json",
                "as_of": AS_OF,
                "question": item["question"],
            }
        )

    # Vulnerability detections are deliberately varied while their playbook has no record_age check.
    for i, age in enumerate((30, 80_000)):
        case_id = f"source_vuln_detected_{'fresh' if i == 0 else 'old'}"
        item = source(case_id, "source_vuln_critical")
        response = search_response(item)
        for hit in response["hits"]["hits"]:
            from datetime import datetime

            hit["_source"]["vulnerability"]["detected_at"] = stamp(age)
        write(ROOT / "cases" / f"{case_id}.json", item)
        labels.append(
            {
                "case_id": case_id,
                "authored_at": "2026-10-20",
                "reviewer": "synthetic-label-author",
                "outcome": "unresolved",
                "sensor_detected": False,
                "rationale": "Detection time varies, but vuln_review has no record_age check and retains its existing priority and version checks.",
                "expected_observations": {
                    "checks": {
                        "vuln_nonzero": "passed",
                        "vuln_priority": "passed",
                        "vuln_versions": "passed",
                    },
                    "fetch": {"vuln_rows": "rows"},
                    "no_check_ids": ["auth_recency", "vuln_recency"],
                },
                "required_findings": [],
                "permitted_findings": [],
            }
        )
        src_manifest.append(
            {
                "case_id": case_id,
                "stage": "source",
                "language": "en",
                "topic_id": "vuln_review",
                "partition": "holdout",
                "incident_id": f"soc007-src-{len(src_manifest):03d}",
                "dedup_key": "family-vuln-detection-age",
                "entity_keys": ["202", "CVE-2099-0001"],
                "input_path": f"cases/{case_id}.json",
                "as_of": AS_OF,
                "question": "Investigate vulnerability review.",
            }
        )

    pack_specs = [
        ("pack_guess_fresh", "auth_guess_11", "passed", "attack"),
        ("pack_guess_stale", "auth_guess_11", "failed", "attack"),
        ("pack_authorized_fresh", "auth_authorized_11", "passed", "benign"),
        ("pack_authorized_stale", "auth_authorized_11", "failed", "benign"),
        ("pack_recency_unknown", "auth_guess_11", "unknown", "attack"),
        ("pack_recency_denied", "auth_guess_11", "denied", "attack"),
        ("pack_recency_bad_binding", "auth_guess_11", "failed", "attack"),
        ("pack_vuln_gap_wrong_topic", "vuln_critical_exploited", "unknown", "attack"),
        ("pack_guess_stale_es", "auth_guess_11", "failed", "attack"),
    ]
    scripts = json.loads((V2 / "scripts.json").read_text())
    scripts["scripts"]["propose_auth_recency_gap"] = {
        "kind": "findings",
        "stop_reason": "end_turn",
        "guardrail_intervened": False,
        "findings": [
            {
                "finding_id": "referral",
                "kind": "recommendation",
                "template_id": "auth_volume_review",
                "bindings": {
                    "n": {
                        "select": {"fetch_id": "auth_rows", "kind": "aggregate", "field": "count"}
                    }
                },
            },
            {
                "finding_id": "gap1",
                "kind": "observation",
                "template_id": "auth_recency_gap",
                "bindings": {
                    "o": {
                        "select": {"check_id": "auth_recency", "kind": "check", "field": "outcome"}
                    }
                },
            },
        ],
    }
    scripts["scripts"]["propose_vuln_and_auth_recency_gap"] = {
        "kind": "findings",
        "stop_reason": "end_turn",
        "guardrail_intervened": False,
        "findings": [
            {
                "finding_id": "referral",
                "kind": "recommendation",
                "template_id": "vuln_priority_review",
                "bindings": {
                    "o": {
                        "select": {"check_id": "vuln_priority", "kind": "check", "field": "outcome"}
                    }
                },
            },
            {
                "finding_id": "gap1",
                "kind": "observation",
                "template_id": "auth_recency_gap",
                "bindings": {
                    "o": {
                        "select": {"check_id": "vuln_priority", "kind": "check", "field": "outcome"}
                    }
                },
            },
        ],
    }
    scripts["scripts"]["propose_auth_recency_gap_bad_binding"] = {
        "kind": "findings",
        "stop_reason": "end_turn",
        "guardrail_intervened": False,
        "findings": [
            {
                "finding_id": "referral",
                "kind": "recommendation",
                "template_id": "auth_volume_review",
                "bindings": {
                    "n": {
                        "select": {"fetch_id": "auth_rows", "kind": "aggregate", "field": "count"}
                    }
                },
            },
            {
                "finding_id": "gap1",
                "kind": "observation",
                "template_id": "auth_recency_gap",
                "bindings": {
                    "o": {
                        "select": {"fetch_id": "auth_rows", "kind": "aggregate", "field": "count"}
                    }
                },
            },
        ],
    }
    casescripts = scripts["cases"]
    labels_pack = []
    pack_manifest = []
    for i, (case_id, base, recency, truth) in enumerate(pack_specs):
        pack = json.loads((V2 / "cases" / f"{base}.json").read_text())
        pack["question_id"] = "00000000-0000-5000-8000-" + f"{i + 200:012d}"
        if case_id.startswith("pack_vuln"):
            # Keep the vulnerability topic; the proposal is intentionally unknown to that catalog.
            pass
        else:
            add_recency(pack, recency)
        if case_id == "pack_recency_denied":
            for fetch in pack["fetches"]:
                if fetch["fetch_id"] == "auth_rows":
                    fetch["state"] = "denied"
                    fetch["rows"] = []
                    fetch["count"] = None
                    fetch["items"] = []
            for check in pack["checks"]:
                check["outcome"] = "denied"
            for evidence_item in pack["items"]:
                if evidence_item["kind"] == "check":
                    evidence_item["values"] = {"outcome": "denied"}
            pack["sha256"] = sha({k: v for k, v in pack.items() if k != "sha256"})
        write(ROOT / "cases" / f"{case_id}.json", pack)
        script_name = (
            "propose_auth_recency_gap_bad_binding"
            if case_id == "pack_recency_bad_binding"
            else "propose_vuln_and_auth_recency_gap"
            if case_id == "pack_vuln_gap_wrong_topic"
            else "propose_auth_recency_gap"
        )
        if case_id == "pack_vuln_gap_wrong_topic":
            # Runner addition: template proposal remains auth_recency_gap against vuln_review.
            pass
        casescripts[case_id] = script_name
        expected_disclosure = (
            ["auth_recency_gap"]
            if recency == "failed"
            and "vuln" not in case_id
            and case_id != "pack_recency_bad_binding"
            else []
        )
        if case_id in {"pack_recency_unknown", "pack_recency_denied"}:
            expected_disclosure = []
        source_label = next(
            x
            for x in json.loads((V2 / "labels.json").read_text())["labels"]
            if x["case_id"] == base
        )
        label = copy.deepcopy(source_label)
        label["case_id"] = case_id
        label["authored_at"] = "2026-10-20"
        label["outcome"] = "confirmed_attack" if truth == "attack" else "authorized_benign"
        label["rationale"] = (
            "The attack or authorized-test truth is unchanged by record freshness; recency affects only the disclosure."
            if "authorized" in case_id or "guess" in case_id
            else "The scripted disclosure is rejected because its check or evidence relation is invalid for this topic."
        )
        label.setdefault("expected_observations", {}).setdefault("checks", {})["auth_recency"] = (
            recency
        )
        label["expected_disclosures"] = expected_disclosure
        if case_id in {"pack_guess_stale", "pack_authorized_stale", "pack_guess_stale_es"}:
            label["permitted_findings"].append(
                {"template_id": "auth_recency_gap", "bindings": {"o": ["outcome", "failed"]}}
            )
        label["expected_escalation"] = base == "auth_guess_11" or base == "auth_authorized_11"
        labels_pack.append(label)
        pack_manifest.append(
            {
                "case_id": case_id,
                "stage": "pack",
                "language": "es" if case_id.endswith("_es") else "en",
                "topic_id": "vuln_review" if "vuln" in case_id else "auth_review",
                "partition": "holdout",
                "incident_id": f"soc007-pack-{i:03d}",
                "dedup_key": "family-vuln-gap-proposal"
                if "vuln" in case_id
                else "family-auth-guess",
                "entity_keys": ["304", "CVE-2099-0001"]
                if "vuln" in case_id
                else ["102", "192.0.2.32"],
                "input_path": f"cases/{case_id}.json",
                "as_of": AS_OF,
                "question": "Investigue la revisión de autenticación."
                if case_id.endswith("_es")
                else "Investigate vulnerability review."
                if "vuln" in case_id
                else "Investigate authentication review.",
            }
        )

    # Preserve all v2 pack cases and source coverage, with additional v3 observations.
    old_manifest = json.loads((V2 / "manifest.json").read_text())
    old_entries = old_manifest["cases"]
    old_labels = json.loads((V2 / "labels.json").read_text())["labels"]
    for label in old_labels:
        case_id = label["case_id"]
        entry = next(e for e in old_entries if e["case_id"] == case_id)
        is_vuln = case_id.startswith("source_vuln") or case_id.startswith("vuln_")
        if case_id == "source_spanish":
            observations = label.get("expected_observations", {})
            observations.get("checks", {}).pop("auth_recency", None)
            observations.get("check_explanations", {}).pop("auth_recency", None)
        if entry["stage"] == "source" and not is_vuln:
            case = json.loads((ROOT / entry["input_path"]).read_text())
            search = next(r for r in case["responses"] if r["path"] == "/_search")
            if search["status"] == 403:
                label.setdefault("expected_observations", {}).setdefault("checks", {})[
                    "auth_recency"
                ] = "denied"
                label["expected_observations"].setdefault("check_explanations", {})[
                    "auth_recency"
                ] = {
                    "invalid_timestamp_rows": 0,
                    "returned_rows_only": True,
                    "approximate_total_noted": False,
                    "first_page_only": False,
                }
                continue
            hits = search["response"].get("hits", {}).get("hits", [])
            from datetime import datetime

            valid = []
            invalid = 0
            for hit in hits:
                value = hit.get("_source", {}).get("@timestamp")
                try:
                    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                    if parsed.utcoffset() is None:
                        raise ValueError
                    valid.append(parsed)
                except (AttributeError, ValueError):
                    invalid += 1
            outcome = (
                "unknown"
                if not hits or not valid
                else "passed"
                if (datetime(2026, 10, 17, 12, tzinfo=UTC) - max(valid)).total_seconds() <= 3600
                else "failed"
            )
            label.setdefault("expected_observations", {}).setdefault("checks", {})[
                "auth_recency"
            ] = outcome
            label["expected_observations"].setdefault("check_explanations", {})["auth_recency"] = {
                "invalid_timestamp_rows": invalid,
                "returned_rows_only": True,
                "approximate_total_noted": search["response"]["hits"]["total"]["relation"] == "gte",
                "first_page_only": False,
            }
        elif entry["stage"] == "pack" and not is_vuln:
            case = json.loads((ROOT / entry["input_path"]).read_text())
            fetch = next(f for f in case["fetches"] if f["fetch_id"] == "auth_rows")
            if fetch["state"] == "denied":
                outcome = "denied"
            else:
                times = []
                for row in fetch["rows"]:
                    try:
                        from datetime import datetime

                        parsed = datetime.fromisoformat(
                            row["values"]["timestamp"].replace("Z", "+00:00")
                        )
                        if (
                            fetch["window"]["start"]
                            <= parsed.isoformat().replace("+00:00", "Z")
                            < fetch["window"]["end"]
                        ):
                            times.append(parsed)
                    except (KeyError, TypeError, ValueError):
                        pass
                outcome = (
                    "unknown"
                    if fetch["state"] != "rows" or not times
                    else "passed"
                    if (datetime(2026, 10, 17, 12, tzinfo=UTC) - max(times)).total_seconds() <= 3600
                    else "failed"
                )
            add_recency(case, outcome)
            write(ROOT / entry["input_path"], case)
            label.setdefault("expected_observations", {}).setdefault("checks", {})[
                "auth_recency"
            ] = outcome
            label["expected_disclosures"] = []
        elif entry["stage"] == "pack":
            label["expected_disclosures"] = []
    # Keep derived catalog identities deterministic and tied to the actual records.
    content_hash = hashlib.sha256()
    for path in sorted((ROOT / "catalog").rglob("*.json")):
        relative = path.relative_to(ROOT / "catalog")
        payload = relative.as_posix().encode() + b"\0" + path.read_bytes() + b"\0"
        if relative.parts[0] != "context":
            content_hash.update(payload)
    for path in sorted((ROOT / "catalog/context").glob("*.json")):
        record = json.loads(path.read_text())
        record["content_sha"] = content_hash.hexdigest()[:40]
        record["sha256"] = sha({k: v for k, v in record.items() if k != "sha256"})
        write(path, record)
    content_pack_hash = hashlib.sha256()
    for path in sorted((ROOT / "catalog").rglob("*.json")):
        relative = path.relative_to(ROOT / "catalog")
        content_pack_hash.update(relative.as_posix().encode() + b"\0" + path.read_bytes() + b"\0")
    for entry in old_entries + pack_manifest:
        if entry["stage"] != "pack":
            continue
        pack_path = ROOT / entry["input_path"]
        pack = json.loads(pack_path.read_text())
        pack["content_sha"] = content_hash.hexdigest()[:40]
        pack["sha256"] = sha({k: v for k, v in pack.items() if k != "sha256"})
        write(pack_path, pack)
    all_entries = old_entries + src_manifest + pack_manifest
    # V2 cases retain their original scenario truth and are in the new source-capable catalog.
    for entry in all_entries:
        path = ROOT / entry["input_path"]
        case_data = json.loads(path.read_text())
        entity_keys: set[str] = set()
        if entry["stage"] == "source":
            for reply in case_data.get("responses", []):
                body = reply.get("response", {})
                hits = body.get("hits", {}).get("hits", []) if isinstance(body, dict) else []
                for hit in hits:
                    raw = hit.get("_source", {})
                    for value in (
                        raw.get("agent", {}).get("id"),
                        raw.get("data", {}).get("srcip"),
                        raw.get("vulnerability", {}).get("id"),
                    ):
                        if isinstance(value, str):
                            entity_keys.add(value)
        else:
            for evidence_item in case_data.get("items", []):
                values = evidence_item.get("values", {})
                for field in ("agent.id", "data.srcip", "vulnerability.id"):
                    value = values.get(field)
                    if isinstance(value, str):
                        entity_keys.add(value)
        if entity_keys:
            entry["entity_keys"] = sorted(entity_keys)
        if entry["stage"] == "source":
            entry["site"] = case_data["site"]
            entry["principal"] = case_data["principal"]
            entry["responses"] = case_data["responses"]
        entry["input_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    parent = list(range(len(all_entries)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    owners: dict[str, int] = {}
    for index, entry in enumerate(all_entries):
        keys = [*entry["entity_keys"], "dedup:" + entry["dedup_key"]]
        for key in keys:
            if key in owners:
                parent[find(index)] = find(owners[key])
            else:
                owners[key] = index
    component_partition: dict[int, str] = {}
    for index, entry in enumerate(all_entries):
        root = find(index)
        if entry["partition"] == "holdout":
            component_partition[root] = "holdout"
        else:
            component_partition.setdefault(root, "dev")
    for index, entry in enumerate(all_entries):
        entry["partition"] = component_partition[find(index)]
    identities = copy.deepcopy(old_manifest["identities"])
    identities["content_sha"] = content_hash.hexdigest()[:40]
    identities["content_pack_sha256"] = content_pack_hash.hexdigest()
    manifest = {
        "schema_version": "1",
        "corpus_id": "replay-synthetic-v3",
        "created_at": "2026-10-20",
        "synthetic": True,
        "identities": identities,
        "escalation_template_ids": old_manifest["escalation_template_ids"],
        "deterministic_rules": old_manifest["deterministic_rules"],
        "cases": all_entries,
    }
    write(ROOT / "manifest.json", manifest)
    holdout_text = "".join(
        f"{digest}  {path}\n"
        for path, digest in sorted(
            (e["input_path"], e["input_sha256"]) for e in all_entries if e["partition"] == "holdout"
        )
    )
    (ROOT / "holdout.lock").write_text(holdout_text, encoding="ascii")


if __name__ == "__main__":
    main()
