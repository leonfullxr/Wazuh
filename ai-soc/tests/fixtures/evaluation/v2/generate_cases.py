"""Generate the frozen synthetic SOC-006 replay fixtures using only the stdlib."""

from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent
AS_OF = "2026-10-17T12:00:00.000000Z"
ISSUER = "https://issuer.example.test"
POLICY_HASH = hashlib.sha256(b"soc006 synthetic policy").hexdigest()
NAMESPACE = uuid.UUID("0b8f7c3e-5d2a-4e61-9a7c-3f1e2d4c5b6a")


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def sha(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def write(path: Path, value: object) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + "\n").encode("ascii")
    path.write_bytes(data)
    return data


def source_response(
    method: str, route: str, body: object, status: int, payload: object
) -> dict[str, object]:
    return {
        "method": method,
        "path": route,
        "body_sha256": sha(body),
        "status": status,
        "response": payload,
    }


def eid(case: str, key: str) -> str:
    return "ev1_" + hashlib.sha256(f"soc006|{case}|{key}".encode()).hexdigest()


def pack_identity(case: str) -> str:
    if case in {"auth_guess_11", "auth_authorized_11", "auth_guess_11_es"}:
        return "auth-twin-family"
    if case in {
        "vuln_critical_exploited",
        "vuln_critical_not_exploited",
        "vuln_critical_es",
    }:
        return "vuln-twin-family"
    return case


def digest_catalog(include_context: bool) -> str:
    h = hashlib.sha256()
    for path in sorted((ROOT / "catalog").rglob("*.json")):
        rel = path.relative_to(ROOT / "catalog")
        if not include_context and rel.parts[0] == "context":
            continue
        h.update(rel.as_posix().encode() + b"\0" + path.read_bytes() + b"\0")
    return h.hexdigest()


def catalog() -> tuple[str, str]:
    topics = {
        "auth_review": {
            "schema_version": "1",
            "topic_id": "auth_review",
            "name": {"en": "Authentication review", "es": "Revision de autenticacion"},
            "aliases": [
                {
                    "alias_id": "auth_review_en",
                    "language": "en",
                    "text": "authentication review",
                    "normalized": "authentication review",
                    "boundary": "phrase",
                    "topic_id": "auth_review",
                },
                {
                    "alias_id": "auth_review_es",
                    "language": "es",
                    "text": "revision de autenticacion",
                    "normalized": "revision de autenticacion",
                    "boundary": "phrase",
                    "topic_id": "auth_review",
                },
            ],
            "public_document": {
                "document_id": "auth_review_guide",
                "language": "en",
                "source_path": "public-docs/en/auth_review.md",
                "heading": "Authentication failure review",
                "anchor": "authentication-failure-review",
                "sha256": "fe27839ac11ff3286eb6d6e82cf21d372f63c3962f6efb70acb026810380832d",
                "published_path": "en/auth-review.html",
            },
            "playbook_id": "auth_review_playbook",
            "finding_template_ids": [
                "auth_count",
                "auth_sample",
                "auth_volume_review",
                "auth_priority_observed",
                "auth_source_gap",
            ],
            "fetch_bindings": [],
        },
        "vuln_review": {
            "schema_version": "1",
            "topic_id": "vuln_review",
            "name": {"en": "Vulnerability review", "es": "Revision de vulnerabilidades"},
            "aliases": [
                {
                    "alias_id": "vuln_review_en",
                    "language": "en",
                    "text": "vulnerability review",
                    "normalized": "vulnerability review",
                    "boundary": "phrase",
                    "topic_id": "vuln_review",
                },
                {
                    "alias_id": "vuln_review_es",
                    "language": "es",
                    "text": "revision de vulnerabilidades",
                    "normalized": "revision de vulnerabilidades",
                    "boundary": "phrase",
                    "topic_id": "vuln_review",
                },
            ],
            "public_document": {
                "document_id": "vuln_review_guide",
                "language": "en",
                "source_path": "public-docs/en/vuln_review.md",
                "heading": "Vulnerability record review",
                "anchor": "vulnerability-record-review",
                "sha256": "52a0a9a6374f6ff9961e9e1a59d4862c689c9b13e02057513210c4a7475f0a4d",
                "published_path": "en/vulnerability-review.html",
            },
            "playbook_id": "vuln_review_playbook",
            "finding_template_ids": [
                "vuln_count",
                "vuln_sample",
                "vuln_priority_review",
                "vuln_version_gap",
            ],
            "fetch_bindings": [],
        },
    }
    playbooks = {
        "auth_review": {
            "schema_version": "1",
            "playbook_id": "auth_review_playbook",
            "topic_id": "auth_review",
            "title": {
                "en": "Authentication failure review",
                "es": "Revision de fallos de autenticacion",
            },
            "internal_context": (
                "Review visible authentication failure records in a rolling 24-hour window. "
                "Counts are matching visible records only."
            ),
            "steps": [
                {
                    "kind": "fetch",
                    "step_id": "auth_rows_step",
                    "fetch_id": "auth_rows",
                    "template_id": "alerts_rows_v1",
                    "window_default": {"unit": "hours", "amount": 24},
                    "filters": [
                        {"field": "rule.groups", "op": "eq", "value": "authentication_failed"}
                    ],
                    "label": {
                        "en": "Authentication failure records",
                        "es": "Registros de fallos de autenticacion",
                    },
                },
                {
                    "kind": "compare_count",
                    "step_id": "auth_nonzero_step",
                    "check_id": "auth_nonzero",
                    "left_fetch_id": "auth_rows",
                    "op": "gte",
                    "right": {"kind": "literal", "value": 1},
                    "label": {
                        "en": "At least one matching record",
                        "es": "Al menos un registro coincidente",
                    },
                },
                {
                    "kind": "compare_count",
                    "step_id": "auth_volume_step",
                    "check_id": "auth_volume",
                    "left_fetch_id": "auth_rows",
                    "op": "gte",
                    "right": {"kind": "literal", "value": 10},
                    "label": {
                        "en": "Review volume threshold",
                        "es": "Umbral de volumen para revision",
                    },
                },
                {
                    "kind": "field_present",
                    "step_id": "auth_sources_step",
                    "check_id": "auth_sources",
                    "fetch_id": "auth_rows",
                    "field": "data.srcip",
                    "quantifier": "all",
                    "label": {
                        "en": "Source address field coverage",
                        "es": "Cobertura del campo de direccion de origen",
                    },
                },
                {
                    "kind": "expectation_match",
                    "step_id": "auth_priority_step",
                    "check_id": "auth_priority",
                    "fetch_id": "auth_rows",
                    "field": "rule.level",
                    "expectation_id": "auth_priority",
                    "quantifier": "any",
                    "label": {
                        "en": "Higher severity rule observed",
                        "es": "Regla de nivel superior observada",
                    },
                },
            ],
        },
        "vuln_review": {
            "schema_version": "1",
            "playbook_id": "vuln_review_playbook",
            "topic_id": "vuln_review",
            "title": {
                "en": "Vulnerability record review",
                "es": "Revision de registros de vulnerabilidades",
            },
            "internal_context": (
                "Review visible High and Critical vulnerability records in a rolling "
                "24-hour window. Checks describe returned rows only."
            ),
            "steps": [
                {
                    "kind": "fetch",
                    "step_id": "vuln_rows_step",
                    "fetch_id": "vuln_rows",
                    "template_id": "vulnerabilities_rows_v1",
                    "window_default": {"unit": "hours", "amount": 24},
                    "filters": [
                        {
                            "field": "vulnerability.severity",
                            "op": "in",
                            "value": ["High", "Critical"],
                        }
                    ],
                    "label": {
                        "en": "High and Critical vulnerability records",
                        "es": "Registros de vulnerabilidad High y Critical",
                    },
                },
                {
                    "kind": "compare_count",
                    "step_id": "vuln_nonzero_step",
                    "check_id": "vuln_nonzero",
                    "left_fetch_id": "vuln_rows",
                    "op": "gte",
                    "right": {"kind": "literal", "value": 1},
                    "label": {
                        "en": "At least one matching record",
                        "es": "Al menos un registro coincidente",
                    },
                },
                {
                    "kind": "field_present",
                    "step_id": "vuln_versions_step",
                    "check_id": "vuln_versions",
                    "fetch_id": "vuln_rows",
                    "field": "package.version",
                    "quantifier": "all",
                    "label": {
                        "en": "Package version field coverage",
                        "es": "Cobertura del campo de version del paquete",
                    },
                },
                {
                    "kind": "expectation_match",
                    "step_id": "vuln_priority_step",
                    "check_id": "vuln_priority",
                    "fetch_id": "vuln_rows",
                    "field": "vulnerability.severity",
                    "expectation_id": "vuln_priority",
                    "quantifier": "any",
                    "label": {
                        "en": "Critical severity observed",
                        "es": "Severidad Critical observada",
                    },
                },
            ],
        },
    }
    expectations = [
        {
            "schema_version": "1",
            "expectation_id": "auth_priority",
            "topic_id": "auth_review",
            "field": "rule.level",
            "op": "gte",
            "value": 10,
            "source": "content",
            "version": "1",
        },
        {
            "schema_version": "1",
            "expectation_id": "vuln_priority",
            "topic_id": "vuln_review",
            "field": "vulnerability.severity",
            "op": "eq",
            "value": "Critical",
            "source": "content",
            "version": "1",
        },
    ]
    templates = [
        (
            "auth_count",
            "auth_review",
            "observation",
            {"n": ["count"]},
            {
                "en": "Matching visible records in this read: {n}; visibility may be restricted.",
                "es": (
                    "Registros visibles coincidentes en esta lectura: {n}; la visibilidad "
                    "puede estar restringida."
                ),
            },
            [{"check_id": "auth_nonzero", "outcome": "passed"}],
            ["aggregate"],
            [],
        ),
        (
            "auth_sample",
            "auth_review",
            "observation",
            {
                "agent": ["agent.id"],
                "rule": ["rule.id"],
                "source": ["data.srcip"],
                "time": ["timestamp"],
            },
            {
                "en": (
                    "One returned record has agent {agent}, rule {rule}, source address "
                    "{source}, and timestamp {time}."
                ),
                "es": (
                    "Un registro devuelto tiene el agente {agent}, la regla {rule}, la "
                    "direccion de origen {source} y la fecha {time}."
                ),
            },
            [],
            ["row"],
            [{"kind": "same_record", "bindings": ["agent", "rule", "source", "time"]}],
        ),
        (
            "auth_volume_review",
            "auth_review",
            "recommendation",
            {"n": ["count"]},
            {
                "en": (
                    "This read contains {n} matching visible records. Visibility may be "
                    "restricted. Refer the volume for manual review; the threshold is not "
                    "an attack verdict."
                ),
                "es": (
                    "Esta lectura contiene {n} registros visibles coincidentes. La "
                    "visibilidad puede estar restringida. Remita el volumen a revision "
                    "manual; el umbral no determina que sea un ataque."
                ),
            },
            [{"check_id": "auth_volume", "outcome": "passed"}],
            ["aggregate"],
            [],
        ),
        (
            "auth_priority_observed",
            "auth_review",
            "observation",
            {"o": ["outcome"]},
            {
                "en": "A rule level threshold check passed for returned rows only; outcome {o}.",
                "es": (
                    "La comprobacion del umbral de nivel de regla se cumplio solo para "
                    "las filas devueltas; resultado {o}."
                ),
            },
            [{"check_id": "auth_priority", "outcome": "passed"}],
            ["check"],
            [],
        ),
        (
            "auth_source_gap",
            "auth_review",
            "observation",
            {"o": ["outcome"]},
            {
                "en": (
                    "A source address was absent from at least one returned row; outcome "
                    "{o}. This check describes returned rows only."
                ),
                "es": (
                    "Falto una direccion de origen en al menos una fila devuelta; "
                    "resultado {o}. Esta comprobacion describe solo las filas devueltas."
                ),
            },
            [{"check_id": "auth_sources", "outcome": "failed"}],
            ["check"],
            [],
        ),
        (
            "vuln_count",
            "vuln_review",
            "observation",
            {"n": ["count"]},
            {
                "en": "Matching visible records in this read: {n}; visibility may be restricted.",
                "es": (
                    "Registros visibles coincidentes en esta lectura: {n}; la visibilidad "
                    "puede estar restringida."
                ),
            },
            [{"check_id": "vuln_nonzero", "outcome": "passed"}],
            ["aggregate"],
            [],
        ),
        (
            "vuln_sample",
            "vuln_review",
            "observation",
            {
                "agent": ["agent.id"],
                "cve": ["vulnerability.id"],
                "package": ["package.name"],
                "version": ["package.version"],
                "severity": ["vulnerability.severity"],
                "detected": ["vulnerability.detected_at"],
            },
            {
                "en": (
                    "One returned record identifies agent {agent}, vulnerability {cve}, "
                    "package {package} version {version}, severity {severity}, and "
                    "detection time {detected}."
                ),
                "es": (
                    "Un registro devuelto identifica el agente {agent}, la vulnerabilidad "
                    "{cve}, el paquete {package} version {version}, severidad {severity} y "
                    "fecha de deteccion {detected}."
                ),
            },
            [],
            ["row"],
            [
                {
                    "kind": "same_record",
                    "bindings": ["agent", "cve", "package", "version", "severity", "detected"],
                }
            ],
        ),
        (
            "vuln_priority_review",
            "vuln_review",
            "recommendation",
            {"o": ["outcome"]},
            {
                "en": (
                    "The configured priority severity check passed for returned rows only; "
                    "outcome {o}. Refer the record for manual review of affected status and "
                    "inventory age."
                ),
                "es": (
                    "La comprobacion configurada de prioridad por severidad se cumplio "
                    "solo para las filas devueltas; resultado {o}. Remita el registro a "
                    "revision manual del estado de afectacion y la antiguedad del inventario."
                ),
            },
            [{"check_id": "vuln_priority", "outcome": "passed"}],
            ["check"],
            [],
        ),
        (
            "vuln_version_gap",
            "vuln_review",
            "observation",
            {"o": ["outcome"]},
            {
                "en": (
                    "Package version was absent from at least one returned row; outcome "
                    "{o}. This check describes returned rows only."
                ),
                "es": (
                    "Falto la version del paquete en al menos una fila devuelta; resultado "
                    "{o}. Esta comprobacion describe solo las filas devueltas."
                ),
            },
            [{"check_id": "vuln_versions", "outcome": "failed"}],
            ["check"],
            [],
        ),
    ]
    for topic, value in topics.items():
        write(ROOT / f"catalog/topics/{topic}.json", value)
    for topic, value in playbooks.items():
        write(ROOT / f"catalog/playbooks/{topic}.json", value)
    for value in expectations:
        write(ROOT / f"catalog/expectations/{value['expectation_id']}.json", value)
    for tid, topic, kind, binds, texts, required, allowed, relations in templates:
        write(
            ROOT / f"catalog/finding-templates/{tid}.json",
            {
                "template_id": tid,
                "topic_id": topic,
                "kind": kind,
                "required_bindings": binds,
                "texts": texts,
                "required_check_outcomes": required,
                "allowed_evidence_kinds": allowed,
                "relations": relations,
            },
        )
    cue_list = [
        {
            "cue_id": "fetch_alerts_en",
            "language": "en",
            "text": "alerts",
            "normalized": "alerts",
            "kind": "fetch",
            "boundary": "word",
            "negation_rule": "direct_negation",
        },
        {
            "cue_id": "fetch_alerts_es",
            "language": "es",
            "text": "alertas",
            "normalized": "alertas",
            "kind": "fetch",
            "boundary": "word",
            "negation_rule": "direct_negation",
        },
        {
            "cue_id": "judgment_recommend_en",
            "language": "en",
            "text": "recommend",
            "normalized": "recommend",
            "kind": "judgment",
            "boundary": "word",
            "negation_rule": "direct_negation",
        },
        {
            "cue_id": "judgment_recommend_es",
            "language": "es",
            "text": "recomienda",
            "normalized": "recomienda",
            "kind": "judgment",
            "boundary": "word",
            "negation_rule": "direct_negation",
        },
        {
            "cue_id": "failure_working_en",
            "language": "en",
            "text": "not working",
            "normalized": "not working",
            "kind": "failure",
            "boundary": "phrase",
        },
        {
            "cue_id": "failure_working_es",
            "language": "es",
            "text": "no funciona",
            "normalized": "no funciona",
            "kind": "failure",
            "boundary": "phrase",
        },
        {
            "cue_id": "failure_investigate_en",
            "language": "en",
            "text": "investigate",
            "normalized": "investigate",
            "kind": "failure",
            "boundary": "word",
        },
        {
            "cue_id": "failure_investiga_es",
            "language": "es",
            "text": "investiga",
            "normalized": "investiga",
            "kind": "failure",
            "boundary": "word",
        },
        {
            "cue_id": "judgment_assess_en",
            "language": "en",
            "text": "assess",
            "normalized": "assess",
            "kind": "judgment",
            "boundary": "word",
            "negation_rule": "direct_negation",
        },
        {
            "cue_id": "judgment_evalua_es",
            "language": "es",
            "text": "evalua",
            "normalized": "evalua",
            "kind": "judgment",
            "boundary": "word",
            "negation_rule": "direct_negation",
        },
    ]
    cues = {
        "version": "1",
        "sha256": sha({"version": "1", "cues": cue_list, "aliases": [], "ambiguities": []}),
        "cues": cue_list,
        "aliases": [],
        "ambiguities": [],
    }
    write(ROOT / "catalog/cues/cues.json", cues)
    content_sha = digest_catalog(False)[:40]
    for topic in topics:
        for lang, context in [
            (
                "en",
                "Use only supplied evidence. Counts are visible records, and "
                "recommendations refer to manual review.",
            ),
            (
                "es",
                "Use solo la evidencia suministrada. Los recuentos son registros "
                "visibles y las recomendaciones solicitan revision manual.",
            ),
        ]:
            write(
                ROOT / f"catalog/context/{topic}.{lang}.json",
                {
                    "schema_version": "1",
                    "topic_id": topic,
                    "language": lang,
                    "content_sha": content_sha,
                    "sha256": hashlib.sha256(context.encode()).hexdigest(),
                    "document_section": None,
                    "internal_context": context,
                    "missing": ["public_document"],
                },
            )
    return content_sha, digest_catalog(True)


PACKS = [
    (
        "auth_guess_11",
        "auth_review",
        "holdout",
        "en",
        "password guessing at 11 failures",
        "confirmed_attack",
        11,
        [5, 5, 5],
        "passed",
        "failed",
        "correct_referral",
    ),
    (
        "auth_authorized_11",
        "auth_review",
        "holdout",
        "en",
        "authorized test with same records",
        "authorized_benign",
        11,
        [5, 5, 5],
        "passed",
        "failed",
        "false_referral",
    ),
    (
        "auth_guess_9",
        "auth_review",
        "holdout",
        "en",
        "real guessing at 9 failures",
        "confirmed_attack",
        9,
        [5, 5, 5],
        "failed",
        "failed",
        "miss",
    ),
    (
        "auth_level10",
        "auth_review",
        "dev",
        "en",
        "level 10 priority boundary",
        "insufficient_evidence",
        1,
        [10],
        "failed",
        "passed",
        "correct_referral",
    ),
    (
        "auth_level9",
        "auth_review",
        "dev",
        "en",
        "level 9 below priority boundary",
        "insufficient_evidence",
        1,
        [9],
        "failed",
        "failed",
        "empty_findings",
    ),
    (
        "auth_missing_srcip",
        "auth_review",
        "dev",
        "en",
        "one row lacks data.srcip",
        "insufficient_evidence",
        11,
        [5, 5],
        "passed",
        "failed",
        "unsupported_claim",
    ),
    (
        "auth_approximate",
        "auth_review",
        "dev",
        "en",
        "approximate total",
        "insufficient_evidence",
        11,
        [5],
        "unknown",
        "failed",
        "omission",
    ),
    (
        "auth_denied",
        "auth_review",
        "holdout",
        "en",
        "denied read",
        "insufficient_evidence",
        None,
        [],
        "denied",
        "denied",
        "invalid_json",
    ),
    (
        "auth_zero",
        "auth_review",
        "dev",
        "en",
        "zero total",
        "insufficient_evidence",
        0,
        [],
        "failed",
        "unknown",
        "empty_findings",
    ),
    (
        "auth_guess_11_es",
        "auth_review",
        "holdout",
        "es",
        "Spanish twin of password guessing",
        "confirmed_attack",
        11,
        [5, 5, 5],
        "passed",
        "failed",
        "omission",
    ),
    (
        "auth_script_unsupported",
        "auth_review",
        "dev",
        "en",
        "scripted unsupported claim",
        "insufficient_evidence",
        3,
        [5],
        "failed",
        "failed",
        "unsupported_claim",
    ),
    (
        "auth_script_omission",
        "auth_review",
        "holdout",
        "en",
        "scripted omission",
        "confirmed_attack",
        11,
        [5, 5],
        "passed",
        "failed",
        "omission",
    ),
    (
        "vuln_critical_exploited",
        "vuln_review",
        "holdout",
        "en",
        "Critical row with known exploitation",
        "confirmed_attack",
        1,
        ["Critical"],
        "passed",
        "passed",
        "correct_referral",
    ),
    (
        "vuln_critical_not_exploited",
        "vuln_review",
        "holdout",
        "en",
        "same inventory without exploitation",
        "authorized_benign",
        1,
        ["Critical"],
        "passed",
        "passed",
        "false_referral",
    ),
    (
        "vuln_high_only",
        "vuln_review",
        "dev",
        "en",
        "High severity only",
        "insufficient_evidence",
        2,
        ["High"],
        "passed",
        "failed",
        "empty_findings",
    ),
    (
        "vuln_missing_version",
        "vuln_review",
        "dev",
        "en",
        "row lacks package.version",
        "insufficient_evidence",
        1,
        ["Critical"],
        "failed",
        "passed",
        "unsupported_claim",
    ),
    (
        "vuln_zero",
        "vuln_review",
        "dev",
        "en",
        "zero vulnerability records",
        "insufficient_evidence",
        0,
        [],
        "failed",
        "unknown",
        "empty_findings",
    ),
    (
        "vuln_page_miss",
        "vuln_review",
        "holdout",
        "en",
        "Critical record beyond displayed page",
        "confirmed_attack",
        21,
        ["High"] * 20,
        "passed",
        "failed",
        "miss",
    ),
    (
        "vuln_critical_es",
        "vuln_review",
        "holdout",
        "es",
        "Spanish twin of exploited Critical row",
        "confirmed_attack",
        1,
        ["Critical"],
        "passed",
        "passed",
        "correct_referral",
    ),
]


def build_pack(spec: tuple[object, ...], content_sha: str) -> dict[str, object]:
    cid, topic, _, _, _, _, count, row_values, count_state, priority, _ = spec
    auth = topic == "auth_review"
    fetch_id = "auth_rows" if auth else "vuln_rows"
    template = "alerts_rows_v1" if auth else "vulnerabilities_rows_v1"
    family = "alerts" if auth else "vulnerabilities"
    rows = []
    items = []
    identity = pack_identity(str(cid))
    snap = {
        "kind": "pit",
        "key": hashlib.sha256(f"{identity}|snap".encode()).hexdigest(),
        "at": "2026-10-17T11:59:00.000000Z",
        "expires_at": "2026-10-17T12:04:00.000000Z",
    }
    countval = count if isinstance(count, int) else 0
    for i, value in enumerate(row_values):
        if auth:
            vals = {
                "timestamp": f"2026-10-17T08:{10 + i:02d}:00.000000Z",
                "agent.id": "101" if spec[2] == "dev" else "102",
                "rule.id": "5710",
                "rule.level": value,
                "rule.groups": ["authentication_failed", "sshd"],
                "data.srcip": None
                if cid == "auth_missing_srcip" and i == 0
                else "192.0.2.31"
                if spec[2] == "dev"
                else "192.0.2.32",
                "data.dstip": None,
            }
        else:
            vals = {
                "agent.id": "201" if spec[2] == "dev" else "202",
                "vulnerability.id": "CVE-2099-0001",
                "vulnerability.severity": value,
                "vulnerability.detected_at": f"2026-10-17T08:{10 + i:02d}:00.000000Z",
                "package.name": "synthetic-agent",
                "package.version": None if cid == "vuln_missing_version" else "1.0.0",
            }
        rowid = eid(identity, f"row-{i}")
        rows.append(
            {
                "evidence_id": rowid,
                "topic_id": topic,
                "fetch_id": fetch_id,
                "record_ref": {
                    "index_alias": "wazuh-eval-2026.10.17",
                    "record_id": f"{identity}-{i:02d}",
                },
                "values": vals,
            }
        )
        items.append(
            {
                "evidence_id": rowid,
                "topic_id": topic,
                "fetch_id": fetch_id,
                "check_id": None,
                "kind": "row",
                "source": {
                    "index_alias": "wazuh-eval-2026.10.17",
                    "record_id": f"{identity}-{i:02d}",
                },
                "snapshot": snap,
                "values": vals,
                "visibility": "full",
                "scope_hash": hashlib.sha256(f"{identity}|scope".encode()).hexdigest(),
            }
        )
    filters = (
        [{"field": "rule.groups", "op": "eq", "value": "authentication_failed"}]
        if auth
        else [{"field": "vulnerability.severity", "op": "in", "value": ["High", "Critical"]}]
    )
    count_obj = (
        None
        if count is None
        else {
            "value": countval,
            "relation": "gte" if cid == "auth_approximate" else "eq",
            "scope": "matching_visible_records",
            "computed_by": "indexer",
            "approximate": cid == "auth_approximate",
        }
    )
    state = "denied" if cid == "auth_denied" else "rows" if row_values else "empty"
    if count_obj is not None:
        countid = eid(identity, "count")
        items.append(
            {
                "evidence_id": countid,
                "topic_id": topic,
                "fetch_id": fetch_id,
                "check_id": None,
                "kind": "aggregate",
                "source": {
                    "template_id": template,
                    "window": {
                        "start": "2026-10-16T12:00:00.000000Z",
                        "end": AS_OF,
                        "semantics": "rolling",
                        "source_text": "rolling:24:hours",
                        "timezone": "UTC",
                        "anchor_at": AS_OF,
                    },
                    "filters": filters,
                    "scope": "matching_visible_records",
                },
                "snapshot": snap,
                "values": {
                    "count": countval,
                    "relation": count_obj["relation"],
                    "approximate": count_obj["approximate"],
                },
                "visibility": "full",
                "scope_hash": hashlib.sha256(f"{identity}|scope".encode()).hexdigest(),
            }
        )
    check_ids = (
        ["auth_nonzero", "auth_volume", "auth_sources", "auth_priority"]
        if auth
        else ["vuln_nonzero", "vuln_versions", "vuln_priority"]
    )
    checks = []
    check_items = []
    for ck in check_ids:
        outcome = "unknown"
        if ck.endswith("nonzero"):
            outcome = (
                "denied"
                if state == "denied"
                else "unknown"
                if count_obj is None
                else "passed"
                if countval > 0 and cid != "auth_approximate"
                else "unknown"
                if cid == "auth_approximate"
                else "failed"
            )
        elif ck in ("auth_volume",):
            outcome = (
                count_state
                if count_state in ("passed", "failed", "unknown", "denied")
                else ("passed" if countval >= 10 else "failed")
            )
        elif ck == "auth_sources":
            outcome = (
                "denied"
                if state == "denied"
                else "unknown"
                if not row_values
                else "failed"
                if cid == "auth_missing_srcip"
                else "passed"
            )
        elif ck in ("auth_priority", "vuln_priority"):
            outcome = priority
        elif ck == "vuln_versions":
            outcome = (
                "unknown"
                if not row_values
                else "failed"
                if cid == "vuln_missing_version"
                else "passed"
            )
        checkid = eid(identity, f"check-{ck}")
        checks.append(
            {
                "check_id": ck,
                "topic_id": topic,
                "label": ck,
                "outcome": outcome,
                "evidence_ids": [checkid],
                "message": "Outcome from frozen rows and count.",
                "expectation_id": "auth_priority"
                if ck == "auth_priority"
                else "vuln_priority"
                if ck == "vuln_priority"
                else None,
            }
        )
        check_items.append(
            {
                "evidence_id": checkid,
                "topic_id": topic,
                "fetch_id": None,
                "check_id": ck,
                "kind": "check",
                "source": {"step_id": ck + "_step", "operand_ids": []},
                "snapshot": snap,
                "values": {"outcome": outcome},
                "visibility": "full",
                "scope_hash": hashlib.sha256(f"{identity}|scope".encode()).hexdigest(),
            }
        )
    fetch = {
        "fetch_id": fetch_id,
        "topic_id": topic,
        "state": state,
        "scope": {
            "environment_id": "soc-eval",
            "template_id": template,
            "index_family": family,
            "filters": filters,
            "visibility": "full",
            "policy_hash": POLICY_HASH,
            "snapshot": "pit",
            "displayed_rows": len(rows),
        },
        "window": {
            "start": "2026-10-16T12:00:00.000000Z",
            "end": AS_OF,
            "semantics": "rolling",
            "source_text": "rolling:24:hours",
            "timezone": "UTC",
            "anchor_at": AS_OF,
        },
        "columns": [],
        "rows": rows,
        "count": count_obj,
        "checks": [],
        "empty_proof": None,
        "next_cursor": None,
        "snapshot_at": snap["at"],
        "snapshot": snap,
        "items": items,
        "buckets": [],
        "bucket_completeness": "complete",
        "message": None,
        "error": {
            "code": "INDEXER_DENIED",
            "message": "Read denied.",
            "retryable": False,
            "trace_id": "00000000000000000000000000000000",
            "details": {},
        }
        if state == "denied"
        else None,
    }
    pack = {
        "schema_version": "1",
        "question_id": str(uuid.uuid5(NAMESPACE, str(cid))),
        "environment_id": "soc-eval",
        "topic_id": topic,
        "policy_hash": POLICY_HASH,
        "content_sha": content_sha,
        "fetches": [fetch],
        "checks": checks,
        "items": items + check_items,
    }
    pack["sha256"] = sha(pack)
    return pack


def main() -> None:
    content_sha, content_pack_sha = catalog()
    cases = []
    holdout = []
    labels = []
    for index, spec in enumerate(PACKS):
        (
            cid,
            topic,
            partition,
            language,
            scenario,
            outcome,
            count,
            rows,
            volume,
            priority,
            script,
        ) = spec
        pack = build_pack(spec, content_sha)
        rel = f"cases/{cid}.json"
        data = write(ROOT / rel, pack)
        question = (
            (
                "Investiga la revision de autenticacion."
                if topic == "auth_review"
                else "Investiga la revision de vulnerabilidades."
            )
            if language == "es"
            else (
                "Investigate authentication review."
                if topic == "auth_review"
                else "Investigate vulnerability review."
            )
        )
        pack_agent = (
            ("101" if partition == "dev" else "102")
            if topic == "auth_review"
            else ("201" if partition == "dev" else "202")
        )
        cases.append(
            {
                "case_id": cid,
                "stage": "pack",
                "incident_id": f"soc006-inc-{index:03d}",
                "entity_keys": [pack_agent, "192.0.2.31" if partition == "dev" else "192.0.2.32"],
                "partition": partition,
                "as_of": AS_OF,
                "language": language,
                "question": question,
                "input_path": rel,
                "input_sha256": hashlib.sha256(data).hexdigest(),
                "dedup_key": "family-auth-guess"
                if cid in ("auth_guess_11", "auth_guess_11_es", "auth_authorized_11")
                else "family-vuln-critical"
                if cid
                in ("vuln_critical_exploited", "vuln_critical_not_exploited", "vuln_critical_es")
                else f"dedup-{cid}",
            }
        )
        if partition == "holdout":
            holdout.append(f"{hashlib.sha256(data).hexdigest()}  {rel}")
        fetch_id = "auth_rows" if topic == "auth_review" else "vuln_rows"
        check_map = {
            "auth_nonzero": "denied"
            if cid == "auth_denied"
            else "unknown"
            if count is None or cid == "auth_approximate"
            else "passed"
            if count
            else "failed",
            "auth_volume": "denied" if cid == "auth_denied" else volume,
            "auth_sources": "denied"
            if cid == "auth_denied"
            else "failed"
            if cid == "auth_missing_srcip"
            else "unknown"
            if not rows
            else "passed",
            "auth_priority": "denied" if cid == "auth_denied" else priority,
            "vuln_nonzero": "unknown" if count is None else "passed" if count else "failed",
            "vuln_versions": "failed"
            if cid == "vuln_missing_version"
            else "unknown"
            if not rows
            else "passed",
            "vuln_priority": priority,
        }
        required = []
        if outcome == "confirmed_attack":
            if topic == "auth_review":
                required = [
                    {"template_id": "auth_volume_review", "bindings": {"n": ["count", count]}}
                ]
            else:
                required = [
                    {
                        "template_id": "vuln_priority_review",
                        "bindings": {"o": ["outcome", "passed"]},
                    }
                ]
        labels.append(
            {
                "case_id": cid,
                "outcome": outcome,
                "sensor_detected": True
                if outcome == "confirmed_attack"
                else False
                if outcome == "authorized_benign"
                else "unknown",
                "required_findings": required,
                "permitted_findings": required.copy(),
                "expected_observations": {
                    "fetch": {
                        fetch_id: "denied" if cid == "auth_denied" else "rows" if rows else "empty"
                    },
                    "count": {
                        fetch_id: {
                            "value": count,
                            "relation": "gte" if cid == "auth_approximate" else "eq",
                            "approximate": cid == "auth_approximate",
                        }
                        if count is not None
                        else {"state": "unknown"}
                    },
                    "checks": {
                        key: value
                        for key, value in check_map.items()
                        if key.startswith("auth_" if topic == "auth_review" else "vuln_")
                    },
                },
                "reviewer": "synthetic-label-author",
                "rationale": scenario
                + (
                    "; manual referral warranted by scenario truth."
                    if outcome == "confirmed_attack"
                    else (
                        "; the evidence is indistinguishable from its paired scenario, "
                        "so this label follows scenario truth."
                    )
                    if cid in ("auth_authorized_11", "vuln_critical_not_exploited")
                    else "; the deterministic check has no signal for this scenario."
                ),
                "authored_at": "2026-10-19",
            }
        )
    write_source_cases(cases, holdout, labels)
    write(
        ROOT / "labels.json",
        {"schema_version": "1", "corpus_id": "replay-synthetic-v2", "labels": labels},
    )
    # Source fixtures use frozen planner-facing indexer responses. Additional
    # source expectations are explicit, reviewed oracle fields in labels.json.
    write(
        ROOT / "manifest.json",
        {
            "schema_version": "1",
            "corpus_id": "replay-synthetic-v2",
            "synthetic": True,
            "created_at": "2026-10-19T00:00:00Z",
            "identities": {
                "code_sha": "runtime",
                "content_sha": content_sha,
                "content_pack_sha256": content_pack_sha,
                "policy_hash": POLICY_HASH,
                "mapping_sha256": "runtime",
                "query_sha256": "runtime",
                "model_capability_sha256": "runtime",
                "prompt_sha256": "runtime",
                "enrichment": {"state": "none"},
            },
            "escalation_template_ids": ["auth_volume_review", "vuln_priority_review"],
            "deterministic_rules": [
                {
                    "rule_id": "auth_volume_passed",
                    "topic_id": "auth_review",
                    "check_id": "auth_volume",
                    "outcome": "passed",
                },
                {
                    "rule_id": "vuln_priority_passed",
                    "topic_id": "vuln_review",
                    "check_id": "vuln_priority",
                    "outcome": "passed",
                },
            ],
            "cases": cases,
        },
    )
    (ROOT / "holdout.lock").write_text("\n".join(sorted(holdout)) + "\n", encoding="ascii")


def write_source_cases(
    cases: list[dict[str, object]], holdout: list[str], labels: list[dict[str, object]]
) -> None:
    source_specs = [
        (
            "source_auth_9",
            "auth_review",
            "dev",
            "en",
            "Investigate authentication review.",
            9,
            [5, 5],
            False,
            False,
        ),
        (
            "source_auth_10",
            "auth_review",
            "holdout",
            "en",
            "Investigate authentication review.",
            10,
            [5, 5],
            False,
            False,
        ),
        (
            "source_vuln_high",
            "vuln_review",
            "dev",
            "en",
            "Investigate vulnerability review.",
            1,
            ["High"],
            False,
            False,
        ),
        (
            "source_vuln_critical",
            "vuln_review",
            "holdout",
            "en",
            "Investigate vulnerability review.",
            1,
            ["Critical"],
            False,
            False,
        ),
        (
            "source_missing_field",
            "auth_review",
            "dev",
            "en",
            "Investigate authentication review.",
            1,
            [5],
            True,
            False,
        ),
        (
            "source_denied",
            "auth_review",
            "holdout",
            "en",
            "Investigate authentication review.",
            None,
            [],
            False,
            True,
        ),
        (
            "source_approximate",
            "auth_review",
            "dev",
            "en",
            "Investigate authentication review.",
            10000,
            [5],
            False,
            False,
        ),
        (
            "source_spanish",
            "vuln_review",
            "holdout",
            "es",
            "Investiga la revision de vulnerabilidades.",
            1,
            ["Critical"],
            False,
            False,
        ),
    ]
    site = {
        "environment_id": "soc-eval",
        "label": "Synthetic evaluation site",
        "enabled": True,
        "indexer_origin": "https://indexer.example.test",
        "private_network_ref": "synthetic-private-network",
        "jwt_issuer": ISSUER,
        "jwt_audience": "soc-eval-api",
        "kms_signing_key_arn": "arn:aws:kms:us-east-1:123456789012:key/synthetic-eval",
        "ca_secret_arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:synthetic-eval-ca",
        "ca_secret_version": "1",
        "ca_sha256": hashlib.sha256(b"synthetic evaluation CA").hexdigest(),
        "group_role_map": {"soc-analysts": ["analyst"]},
        "role_visibility": {"analyst": "full"},
        "allowed_index_patterns": {
            "alerts": ["wazuh-alerts-*"],
            "vulnerabilities": ["wazuh-states-vulnerabilities-*", "wazuh-vulnerabilities-*"],
        },
        "mapping_profile": "wazuh-v4-fixture",
        "policy_version": "1",
        "pit_supported": True,
        "allowed_templates": [
            "alerts_rows_v1",
            "alerts_count_v1",
            "vulnerabilities_rows_v1",
            "vulnerabilities_count_v1",
        ],
        "dls_attestation_version": "1",
        "composite_role_visibility": {"analyst": "full"},
        "expectations": [],
    }
    principal = {
        "issuer": ISSUER,
        "sub": "synthetic-analyst-01",
        "owner_key": hashlib.sha256(f"{ISSUER}\0synthetic-analyst-01".encode()).hexdigest(),
        "groups": ["soc-analysts"],
        "edge": "fixture",
        "authenticated_at": "2026-10-17T11:00:00.000000Z",
        "expires_at": "2026-10-17T13:00:00.000000Z",
        "assertion_hash": hashlib.sha256(b"soc006 synthetic assertion").hexdigest(),
    }
    for index, (cid, topic, partition, lang, question, total, levels, missing, denied) in enumerate(
        source_specs
    ):
        agent = str(301 + index)
        if topic == "auth_review":
            source_fields = [
                "@timestamp",
                "agent.id",
                "agent.name",
                "rule.id",
                "rule.level",
                "rule.groups",
                "data.srcip",
                "data.dstip",
            ]
            hits = []
            for n, level in enumerate(levels):
                src = {} if missing else {"srcip": "192.0.2.41"}
                hits.append(
                    {
                        "_index": "wazuh-alerts-2026.10.17",
                        "_id": f"{cid}-{n}",
                        "_source": {
                            "@timestamp": f"2026-10-17T08:{10 + n:02d}:00.000Z",
                            "agent": {"id": agent},
                            "rule": {
                                "id": "5710",
                                "level": level,
                                "groups": ["authentication_failed"],
                            },
                            "data": src,
                        },
                        "sort": [1792224600000 - n, "wazuh-alerts-2026.10.17", f"{cid}-{n}"],
                    }
                )
            pattern = "wazuh-alerts-*"
        else:
            source_fields = [
                "agent.id",
                "agent.name",
                "vulnerability.id",
                "vulnerability.severity",
                "vulnerability.detected_at",
                "package.name",
                "package.version",
            ]
            hits = []
            for n, severity in enumerate(levels):
                package = {"name": "synthetic-agent"}
                if not missing:
                    package["version"] = "1.0.0"
                hits.append(
                    {
                        "_index": "wazuh-states-vulnerabilities-2026.10.17",
                        "_id": f"{cid}-{n}",
                        "_source": {
                            "@timestamp": f"2026-10-17T08:{10 + n:02d}:00.000Z",
                            "agent": {"id": agent},
                            "vulnerability": {
                                "id": "CVE-2099-0001",
                                "severity": severity,
                                "detected_at": f"2026-10-17T08:{10 + n:02d}:00.000Z",
                            },
                            "package": package,
                        },
                        "sort": [
                            1792224600000 - n,
                            "wazuh-states-vulnerabilities-2026.10.17",
                            f"{cid}-{n}",
                        ],
                    }
                )
            pattern = "wazuh-states-vulnerabilities-*"
        time_field = "@timestamp" if topic == "auth_review" else "vulnerability.detected_at"
        clauses = [
            {"range": {time_field: {"gte": "2026-10-16T12:00:00Z", "lt": "2026-10-17T12:00:00Z"}}}
        ]
        if topic == "auth_review":
            clauses.append({"term": {"rule.groups": "authentication_failed"}})
        else:
            clauses.append({"terms": {"vulnerability.severity": ["High", "Critical"]}})
        query = {"bool": {"filter": clauses}}
        req = {
            "size": 20,
            "query": query,
            "_source": source_fields,
            "sort": [
                {time_field: {"order": "desc"}},
                {"_index": {"order": "desc"}},
                {"_id": {"order": "desc"}},
            ],
            "track_total_hits": True,
            "pit": {"id": f"pit-{cid}", "keep_alive": "5m"},
        }
        responses = []

        request_pattern = (
            "wazuh-states-vulnerabilities-*,wazuh-vulnerabilities-*"
            if topic == "vuln_review"
            else pattern
        )
        pitpath = f"/{request_pattern}/_search/point_in_time?keep_alive=5m"
        validate = f"/{request_pattern}/_validate/query"
        responses.append(source_response("POST", pitpath, None, 200, {"id": f"pit-{cid}"}))
        responses.append(
            source_response("POST", validate, {"query": req["query"]}, 200, {"valid": True})
        )
        if denied:
            responses.append(
                source_response(
                    "POST",
                    "/_search",
                    req,
                    403,
                    {"status": 403, "error": {"type": "security_exception"}},
                )
            )
            responses.append(
                source_response(
                    "DELETE",
                    "/_search/point_in_time",
                    {"pit_id": f"pit-{cid}"},
                    200,
                    {"succeeded": True, "num_freed": 1},
                )
            )
        else:
            total_obj = {"value": total, "relation": "gte" if cid == "source_approximate" else "eq"}
            responses.append(
                source_response(
                    "POST",
                    "/_search",
                    req,
                    200,
                    {"took": 2, "timed_out": False, "hits": {"total": total_obj, "hits": hits}},
                )
            )
            responses.append(
                source_response(
                    "DELETE",
                    "/_search/point_in_time",
                    {"pit_id": f"pit-{cid}"},
                    200,
                    {"succeeded": True, "num_freed": 1},
                )
            )
        source = {
            "case_id": cid,
            "question": question,
            "as_of": AS_OF,
            "site": site,
            "principal": principal,
            "responses": responses,
        }
        rel = f"cases/{cid}.json"
        data = write(ROOT / rel, source)
        case = {
            "case_id": cid,
            "stage": "source",
            "incident_id": f"soc006-src-{index:03d}",
            "entity_keys": [agent, "192.0.2.41" if partition == "dev" else "192.0.2.42"],
            "partition": partition,
            "as_of": AS_OF,
            "language": lang,
            "question": question,
            "input_path": rel,
            "input_sha256": hashlib.sha256(data).hexdigest(),
            "dedup_key": f"source-family-{cid}",
            "site": site,
            "principal": principal,
            "responses": responses,
        }
        cases.append(case)
        if partition == "holdout":
            holdout.append(f"{hashlib.sha256(data).hexdigest()}  {rel}")
        fetch_id = "auth_rows" if topic == "auth_review" else "vuln_rows"
        checks = (
            {
                "auth_nonzero": "denied"
                if denied
                else "unknown"
                if cid == "source_approximate"
                else "passed"
                if total
                else "failed",
                "auth_volume": "denied"
                if denied
                else "unknown"
                if cid == "source_approximate"
                else "passed"
                if total is not None and total >= 10
                else "failed",
                "auth_sources": "denied" if denied else "failed" if missing else "passed",
                "auth_priority": "denied" if denied else "failed",
            }
            if topic == "auth_review"
            else {
                "vuln_nonzero": "denied" if denied else "passed",
                "vuln_versions": "denied" if denied else "failed" if missing else "passed",
                "vuln_priority": "denied"
                if denied
                else "passed"
                if "Critical" in levels
                else "failed",
            }
        )
        row_fields = (
            ["agent.id", "rule.id", "rule.level", "data.srcip", "timestamp"]
            if topic == "auth_review"
            else [
                "agent.id",
                "vulnerability.id",
                "vulnerability.severity",
                "vulnerability.detected_at",
                "package.name",
                "package.version",
            ]
        )
        label = {
            "case_id": cid,
            "outcome": "unresolved",
            "sensor_detected": "unknown",
            "required_findings": [],
            "permitted_findings": [],
            "expected_observations": {
                "language": lang,
                "fetch": {fetch_id: "denied" if denied else "rows"},
                "visibility": {fetch_id: "full"},
                "count": {
                    fetch_id: {
                        "value": total,
                        "relation": "gte" if cid == "source_approximate" else "eq",
                        "approximate": cid == "source_approximate",
                    }
                    if total is not None
                    else {"state": "unknown"}
                },
                "checks": checks,
                "abstention": {fetch_id: denied},
                "row_cardinality": {fetch_id: len(hits)},
                "rows": {
                    fetch_id: [
                        {
                            field: (
                                agent
                                if field == "agent.id"
                                else (
                                    "5710"
                                    if field == "rule.id"
                                    else levels[rowno]
                                    if field in ("rule.level", "vulnerability.severity")
                                    else "192.0.2.41"
                                    if field == "data.srcip" and not missing
                                    else None
                                    if field == "data.srcip" and missing
                                    else "CVE-2099-0001"
                                    if field == "vulnerability.id"
                                    else f"2026-10-17T08:{10 + rowno:02d}:00.000Z"
                                    if field in ("timestamp", "vulnerability.detected_at")
                                    else "synthetic-agent"
                                    if field == "package.name"
                                    else "1.0.0"
                                    if field == "package.version" and not missing
                                    else None
                                )
                            )
                            for field in row_fields
                        }
                        for rowno in range(len(hits))
                    ]
                },
            },
            "reviewer": "synthetic-label-author",
            "rationale": (
                "Source case measures frozen observation replay only; no attack outcome is scored."
            ),
            "authored_at": "2026-10-19",
        }
        labels.append(label)


if __name__ == "__main__":
    main()
