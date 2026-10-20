# pyright: reportPrivateUsage=false

import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Literal

import pytest
from pydantic import ValidationError

from ai_soc.content.builder import (
    ContentBuildError,
    _decode_document,
    _validate_cross_references,
    _validate_finding_templates,
    cue_catalog_digest,
)
from ai_soc.content.catalog import ContentCatalog
from ai_soc.content.finding_catalog import (
    MAX_TOPIC_CONTEXT_BYTES,
    CatalogError,
    topic_context_text,
    validate_prompt_contexts,
    validate_topic_context,
)
from ai_soc.contracts.models import (
    AnonymizationAttestation,
    BuildProvenance,
    CheckOutcome,
    CompareCountStep,
    CueCatalog,
    CueDefinition,
    FetchBinding,
    FetchStep,
    FieldId,
    FindingRelationAggregateScope,
    FindingRelationSameFetch,
    FindingRelationSameRecord,
    FindingTemplate,
    IntegerOperand,
    LocaleText,
    PlaybookDefinition,
    RecordAgeStep,
    RequiredCheckOutcome,
    SolvedCase,
    TemplateId,
    TopicDefinition,
    TopicPromptPack,
)

QA061_FIXTURE = Path(__file__).parent / "data/qa061_variants.json"


def _qa061_fixture() -> dict[str, dict[str, str]]:
    return json.loads(QA061_FIXTURE.read_text(encoding="utf-8"))


def _record_g061(record_property: Callable[[str, str], None], variant: str) -> None:
    record_property("acceptance_ids", "G061")
    record_property("case_id", "B2-G061.anonymized-seed")
    record_property("variant", variant)
    record_property("fixture_sha256", hashlib.sha256(QA061_FIXTURE.read_bytes()).hexdigest())


def _validation_seam(case: SolvedCase) -> None:
    topic = TopicDefinition(
        topic_id="ldap",
        name=LocaleText(en="LDAP", es="LDAP"),
        aliases=[],
        public_document=None,
        playbook_id=None,
        finding_template_ids=[],
        fetch_bindings=[],
    )
    cue_sources: tuple[tuple[Literal["en", "es"], str], ...] = (
        ("en", "alerts"),
        ("es", "alertas"),
    )
    cues = tuple(
        CueCatalog(
            version="1",
            sha256="0" * 64,
            cues=[
                CueDefinition(
                    cue_id=f"fetch_{language}",
                    language=language,
                    text=text,
                    normalized=text,
                    kind="fetch",
                    boundary="word",
                )
            ],
            aliases=[],
            ambiguities=[],
        )
        for language, text in cue_sources
    )
    valid_cues = tuple(
        catalog.model_copy(update={"sha256": cue_catalog_digest(catalog)}) for catalog in cues
    )
    _validate_cross_references({}, (topic,), valid_cues, (), (), (), (case,), ())


def _solved_case(*, description: str, reviewer_id: str, date: str) -> SolvedCase:
    return SolvedCase(
        case_id="synthetic_case",
        topic_id="ldap",
        description=description,
        promotion_status="candidate",
        anonymization_attestation=AnonymizationAttestation(
            reviewer_id=reviewer_id,
            date=date,
        ),
    )


@pytest.mark.parametrize(
    "source",
    [
        b"value: &shared [one, two]\ncopy: *shared\n",
        b"!!python/object/apply:os.system ['echo unsafe']\n",
    ],
)
def test_safe_yaml_rejects_aliases_and_explicit_tags(source: bytes) -> None:
    with pytest.raises((ContentBuildError, ValueError)):
        _decode_document("content/topics/unsafe.yaml", source)


def test_safe_yaml_rejects_duplicate_keys() -> None:
    with pytest.raises(ContentBuildError, match="duplicate YAML key"):
        _decode_document("content/topics/unsafe.yaml", b"topic_id: one\ntopic_id: two\n")


def test_synthetic_solved_case_accepts_human_anonymization_attestation(
    record_property: Callable[[str, str], None],
) -> None:
    _record_g061(record_property, "positive")
    fixture = _qa061_fixture()
    _validation_seam(
        _solved_case(
            description=fixture["positive"]["description"],
            reviewer_id=fixture["positive"]["reviewer_id"],
            date=fixture["positive"]["date"],
        )
    )


def test_synthetic_solved_case_rejects_missing_or_blank_attestation(
    record_property: Callable[[str, str], None],
) -> None:
    _record_g061(record_property, "negative")
    fixture = _qa061_fixture()["negative"]
    with pytest.raises(ValidationError):
        SolvedCase.model_validate(
            {
                "case_id": "synthetic_case",
                "topic_id": "ldap",
                "description": fixture["description"],
                "promotion_status": "candidate",
            }
        )
    with pytest.raises(ContentBuildError, match="reviewer must not be empty"):
        _validation_seam(
            _solved_case(
                description=fixture["description"],
                reviewer_id=fixture["reviewer_id"],
                date=fixture["date"],
            )
        )


def test_solved_case_attestation_accepts_leap_day_and_rejects_invalid_calendar_date(
    record_property: Callable[[str, str], None],
) -> None:
    _record_g061(record_property, "boundary")
    fixture = _qa061_fixture()["boundary"]
    _validation_seam(
        _solved_case(
            description=fixture["description"],
            reviewer_id=fixture["reviewer_id"],
            date=fixture["date"],
        )
    )
    with pytest.raises(ContentBuildError, match="date is invalid"):
        _validation_seam(
            _solved_case(
                description=fixture["description"],
                reviewer_id=fixture["reviewer_id"],
                date=fixture["invalid_date"],
            )
        )


def test_solved_case_secret_sentinel_fails_pack_validation(
    record_property: Callable[[str, str], None],
) -> None:
    _record_g061(record_property, "failure")
    fixture = _qa061_fixture()["failure"]
    with pytest.raises(ContentBuildError, match="secret-like value in solved case"):
        _validation_seam(
            _solved_case(
                description=fixture["description"],
                reviewer_id=fixture["reviewer_id"],
                date=fixture["date"],
            )
        )


def test_finding_template_rejects_unbacked_agent_name_literals() -> None:
    cases = (
        "Agent alice failed.",
        "El agente alice falló.",
        "Agent 007 failed.",
        "El agente 007 fallo.",
    )
    for text in cases:
        template = FindingTemplate(
            template_id="ldap_obs",
            topic_id="ldap",
            kind="observation",
            required_bindings={},
            texts=LocaleText(en=text, es=text),
            required_check_outcomes=[],
            allowed_evidence_kinds=["row"],
            relations=[],
        )
        with pytest.raises(ContentBuildError, match="unbacked literal"):
            _validate_finding_templates((template,))


def test_finding_template_with_bound_agent_placeholder_passes_literal_scan() -> None:
    template = FindingTemplate(
        template_id="ldap_obs",
        topic_id="ldap",
        kind="observation",
        required_bindings={"agent": (FieldId.agent_name,)},
        texts=LocaleText(en="Agent {agent} failed.", es="El agente {agent} falló."),
        required_check_outcomes=[],
        allowed_evidence_kinds=["row"],
        relations=[],
    )
    _validate_finding_templates((template,))


def test_finding_template_rejects_digit_suffix_after_placeholder_segment() -> None:
    template = FindingTemplate(
        template_id="ldap_obs",
        topic_id="ldap",
        kind="observation",
        required_bindings={"slot": (FieldId.agent_name,)},
        texts=LocaleText(en="Agent {slot}007", es="Agente {slot}007"),
        required_check_outcomes=[],
        allowed_evidence_kinds=["row"],
        relations=[],
    )
    with pytest.raises(ContentBuildError, match="unbacked literal"):
        _validate_finding_templates((template,))


@pytest.mark.parametrize(
    "texts",
    [
        LocaleText(en="Rule is approved", es="Regla aprobada"),
        LocaleText(en="Observed {rule", es="Observado {rule"),
        LocaleText(en="Observed {rule[0]}", es="Observado {rule[0]}"),
        LocaleText(en="Observed {rule!r}", es="Observado {rule!r}"),
        LocaleText(en="Observed {rule:>8}", es="Observado {rule:>8}"),
    ],
)
def test_finding_template_rejects_missing_and_nonliteral_placeholders(
    texts: LocaleText,
) -> None:
    template = FindingTemplate(
        template_id="ldap_placeholder_guard",
        topic_id="ldap",
        kind="observation",
        required_bindings={"rule": (FieldId.rule_id,)},
        texts=texts,
        required_check_outcomes=[],
        allowed_evidence_kinds=["row"],
    )
    with pytest.raises(ContentBuildError, match="placeholders do not match bindings"):
        _validate_finding_templates((template,))


def test_finding_template_relation_binding_is_validated_at_build() -> None:
    template = FindingTemplate(
        template_id="ldap_obs",
        topic_id="ldap",
        kind="observation",
        required_bindings={"agent": (FieldId.agent_name,)},
        texts=LocaleText(en="Agent {agent} failed.", es="El agente {agent} falló."),
        required_check_outcomes=[],
        allowed_evidence_kinds=["row"],
        relations=[
            FindingRelationAggregateScope(
                kind="aggregate_scope",
                count_binding="missing_binding",
                entity_bindings={"agent": FieldId.agent_name},
            )
        ],
    )
    with pytest.raises(ContentBuildError, match="unknown count binding"):
        _validate_finding_templates((template,))


@pytest.mark.parametrize(
    ("relation", "error"),
    [
        (
            FindingRelationSameRecord(kind="same_record", bindings=["rule", "unknown"]),
            "unknown bindings",
        ),
        (
            FindingRelationSameFetch(kind="same_fetch", bindings=["rule", "unknown"]),
            "unknown bindings",
        ),
        (
            FindingRelationAggregateScope(
                kind="aggregate_scope",
                count_binding="count",
                entity_bindings={"unknown": FieldId.agent_name},
            ),
            "unknown entity bindings",
        ),
    ],
)
def test_finding_template_rejects_undeclared_relation_bindings(
    relation: FindingRelationSameRecord | FindingRelationSameFetch | FindingRelationAggregateScope,
    error: str,
) -> None:
    required: dict[str, tuple[str, ...]] = {"rule": (FieldId.rule_id,)}
    en = "Observed {rule}"
    es = "Observado {rule}"
    if isinstance(relation, FindingRelationAggregateScope):
        required["count"] = ("count",)
        en += " count {count}"
        es += " cuenta {count}"
    template = FindingTemplate(
        template_id="ldap_relation_guard",
        topic_id="ldap",
        kind="observation",
        required_bindings=required,
        texts=LocaleText(en=en, es=es),
        required_check_outcomes=[],
        allowed_evidence_kinds=["row", "aggregate"],
        relations=[relation],
    )
    with pytest.raises(ContentBuildError, match=error):
        _validate_finding_templates((template,))


def _ldap_topic(*, playbook_id: str | None = None) -> TopicDefinition:
    return TopicDefinition(
        topic_id="ldap",
        name=LocaleText(en="LDAP", es="LDAP"),
        aliases=[],
        public_document=None,
        playbook_id=playbook_id,
        finding_template_ids=[],
        fetch_bindings=[FetchBinding(template_id=TemplateId.alerts_rows_v1, filters=[])],
    )


def _valid_cues() -> tuple[CueCatalog, ...]:
    catalogs: list[CueCatalog] = []
    for language, text in (("en", "alerts"), ("es", "alertas")):
        catalog = CueCatalog(
            version="1",
            sha256="0" * 64,
            cues=[
                CueDefinition(
                    cue_id=f"fetch_{language}",
                    language=language,
                    text=text,
                    normalized=text,
                    kind="fetch",
                    boundary="word",
                )
            ],
            aliases=[],
            ambiguities=[],
        )
        catalogs.append(catalog.model_copy(update={"sha256": cue_catalog_digest(catalog)}))
    return tuple(catalogs)


def _prerequisite_template(*, check_id: str) -> FindingTemplate:
    return FindingTemplate(
        template_id="ldap_visible",
        topic_id="ldap",
        kind="observation",
        required_bindings={"count": ("count",)},
        texts=LocaleText(
            en="Observed {count} visible objects",
            es="Se observaron {count} objetos visibles",
        ),
        required_check_outcomes=[
            RequiredCheckOutcome(check_id=check_id, outcome=CheckOutcome.passed)
        ],
        allowed_evidence_kinds=["aggregate"],
    )


def _declared_check_playbook(*, declared: tuple[str, ...]) -> PlaybookDefinition:
    label = LocaleText(en="checks", es="chequeos")
    return PlaybookDefinition(
        playbook_id="ldap_checks",
        topic_id="ldap",
        title=label,
        internal_context="fixture",
        steps=[
            FetchStep(
                kind="fetch",
                step_id="alerts_fetch",
                label=label,
                fetch_id="alerts",
                template_id=TemplateId.alerts_rows_v1,
                window_default={"unit": "hours", "amount": 24},
                filters=[],
            ),
            *(
                CompareCountStep(
                    kind="compare_count",
                    step_id=f"count_compare_{index}",
                    label=label,
                    check_id=check_id,
                    left_fetch_id="alerts",
                    op="gte",
                    right=IntegerOperand(kind="literal", value=0),
                )
                for index, check_id in enumerate(declared)
            ),
        ],
    )


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("unknown_topic", "finding template references an unknown topic"),
        ("cross_topic_reference", "cross-topic finding template"),
    ],
)
def test_authored_template_topic_references_fail_build_and_loaded_catalog(
    case: str, message: str
) -> None:
    template_id = "vpn_template"
    template = FindingTemplate(
        template_id=template_id,
        topic_id="vpn",
        kind="observation",
        required_bindings={},
        texts=LocaleText(en="VPN observation", es="Observacion VPN"),
        required_check_outcomes=[],
        allowed_evidence_kinds=["row"],
    )
    ldap_topic = _ldap_topic()
    if case == "cross_topic_reference":
        ldap_topic = ldap_topic.model_copy(update={"finding_template_ids": [template_id]})
        topics = (ldap_topic, _ldap_topic().model_copy(update={"topic_id": "vpn"}))
    else:
        topics = (ldap_topic,)
    cues = _valid_cues()

    with pytest.raises(ContentBuildError, match=message):
        _validate_cross_references({}, topics, cues, (), (), (template,), (), ())
    with pytest.raises(ValueError, match=message):
        ContentCatalog(
            _seed_provenance(),
            CueCatalog(version="1", sha256="0" * 64, cues=[], aliases=[], ambiguities=[]),
            topics,
            (),
            templates=(template,),
        )


def test_twenty_templates_per_topic_are_allowed_and_twenty_one_are_rejected() -> None:
    templates = tuple(
        FindingTemplate(
            template_id=f"ldap_obs_{index:02d}",
            topic_id="ldap",
            kind="observation",
            required_bindings={},
            texts=LocaleText(en=f"Observation {index}", es=f"Observacion {index}"),
            required_check_outcomes=[],
            allowed_evidence_kinds=["row"],
        )
        for index in range(20)
    )
    _validate_finding_templates(templates)
    ContentCatalog(
        _seed_provenance(),
        CueCatalog(version="1", sha256="0" * 64, cues=[], aliases=[], ambiguities=[]),
        (_ldap_topic(),),
        (),
        templates=templates,
    )
    overflow = templates + (
        FindingTemplate(
            template_id="ldap_obs_20",
            topic_id="ldap",
            kind="observation",
            required_bindings={},
            texts=LocaleText(en="Observation 20", es="Observacion 20"),
            required_check_outcomes=[],
            allowed_evidence_kinds=["row"],
        ),
    )
    with pytest.raises(ContentBuildError, match="topic exceeds 20 approved finding templates"):
        _validate_finding_templates(overflow)
    with pytest.raises(ValueError, match="topic exceeds 20 approved finding templates"):
        ContentCatalog(
            _seed_provenance(),
            CueCatalog(version="1", sha256="0" * 64, cues=[], aliases=[], ambiguities=[]),
            (_ldap_topic(),),
            (),
            templates=overflow,
        )


def _seed_provenance() -> BuildProvenance:
    return BuildProvenance(
        service_sha="0" * 40,
        content_repository="https://example.test/content",
        content_sha="a" * 40,
        pack_sha256="b" * 64,
        image_digest="sha256:" + "c" * 64,
        docs_origin="https://docs.example.test",
        docs_manifest_sha256="d" * 64,
    )


def _sized_catalog(pack: TopicPromptPack, *, byte_target: int) -> tuple[FindingTemplate, ...]:
    def template(fill: str) -> FindingTemplate:
        return FindingTemplate(
            template_id="ldap_sized",
            topic_id="ldap",
            kind="observation",
            required_bindings={},
            texts=LocaleText(en="Approved observation." + fill, es="Observacion aprobada."),
            required_check_outcomes=[],
            allowed_evidence_kinds=["row"],
        )

    base = len(topic_context_text(pack, (template(""),)).encode("utf-8"))
    remaining = byte_target - base
    filler = "\u00f1" * (remaining // len("\u00f1".encode()))
    if remaining % len("\u00f1".encode()):
        filler += "z"
    sized = template(filler)
    assert len(topic_context_text(pack, (sized,)).encode("utf-8")) == byte_target
    return (sized,)


def test_topic_context_byte_bound_is_exact_at_65536_and_rejects_65537() -> None:
    pack = TopicPromptPack(
        topic_id="ldap",
        language="en",
        content_sha="a" * 40,
        sha256="e" * 64,
        document_section='Quoted "context" with a slash \\ and accented text \u00f1.',
        internal_context="Approved context with both locales and escaped JSON metadata.",
        missing=[],
    )
    at_bound = _sized_catalog(pack, byte_target=MAX_TOPIC_CONTEXT_BYTES)
    exact_text = validate_topic_context(pack, at_bound)
    payload = json.loads(exact_text.removeprefix("APPROVED TOPIC CONTEXT (data): "))
    assert len(exact_text.encode("utf-8")) == MAX_TOPIC_CONTEXT_BYTES
    assert payload["document_section"] == pack.document_section
    assert payload["finding_templates"][0]["texts"]["en"].startswith("Approved observation.\u00f1")
    assert payload["finding_templates"][0]["texts"]["es"] == "Observacion aprobada."
    validate_prompt_contexts((pack,), at_bound)
    over_bound = _sized_catalog(pack, byte_target=MAX_TOPIC_CONTEXT_BYTES + 1)
    with pytest.raises(CatalogError, match="approved topic context exceeds 65536 UTF-8 bytes"):
        validate_topic_context(pack, over_bound)
    with pytest.raises(CatalogError, match="approved topic context exceeds 65536 UTF-8 bytes"):
        validate_prompt_contexts((pack,), over_bound)
    with pytest.raises(ValueError, match="approved topic context exceeds 65536 UTF-8 bytes"):
        ContentCatalog(
            _seed_provenance(),
            CueCatalog(version="1", sha256="0" * 64, cues=[], aliases=[], ambiguities=[]),
            (_ldap_topic(),),
            (pack,),
            templates=over_bound,
        )


def test_empty_catalog_is_rejected_for_runtime_topic_context() -> None:
    pack = TopicPromptPack(
        topic_id="ldap",
        language="en",
        content_sha="a" * 40,
        sha256="e" * 64,
        missing=[],
    )
    with pytest.raises(CatalogError, match="topic has no approved finding templates"):
        validate_topic_context(pack, ())


def test_foreign_topic_template_is_rejected_for_the_runtime_topic() -> None:
    pack = TopicPromptPack(
        topic_id="ldap",
        language="en",
        content_sha="a" * 40,
        sha256="e" * 64,
        missing=[],
    )
    foreign = FindingTemplate(
        template_id="vpn_obs",
        topic_id="vpn",
        kind="observation",
        required_bindings={},
        texts=LocaleText(en="VPN observation", es="Observacion VPN"),
        required_check_outcomes=[],
        allowed_evidence_kinds=["row"],
    )
    with pytest.raises(
        CatalogError, match="finding template is not approved for this topic: vpn_obs"
    ):
        validate_topic_context(pack, (foreign,))


def test_duplicate_template_ids_are_rejected_before_dict_collapse_including_identical() -> None:
    template = FindingTemplate(
        template_id="ldap_obs",
        topic_id="ldap",
        kind="observation",
        required_bindings={},
        texts=LocaleText(en="Observation", es="Observacion"),
        required_check_outcomes=[],
        allowed_evidence_kinds=["row"],
    )
    with pytest.raises(ContentBuildError, match="duplicate finding template IDs"):
        _validate_finding_templates((template, template.model_copy(deep=True)))


def test_undeclared_prerequisite_is_rejected_at_build_and_loaded_catalog() -> None:
    topic = _ldap_topic(playbook_id="ldap_checks")
    playbook = _declared_check_playbook(declared=("ldap_alert_count",))
    template = _prerequisite_template(check_id="undeclared_check")
    with pytest.raises(
        ContentBuildError, match="finding template requires an undeclared playbook check"
    ):
        _validate_cross_references(
            {}, (topic,), _valid_cues(), (playbook,), (), (template,), (), ()
        )
    with pytest.raises(ValueError, match="finding template requires an undeclared playbook check"):
        ContentCatalog(
            _seed_provenance(),
            CueCatalog(version="1", sha256="0" * 64, cues=[], aliases=[], ambiguities=[]),
            (topic,),
            (),
            (playbook,),
            (),
            (template,),
        )


def test_unassociated_playbook_prerequisite_is_rejected_at_build_and_loaded_catalog() -> None:
    topic = _ldap_topic()
    template = _prerequisite_template(check_id="ldap_alert_count")
    with pytest.raises(
        ContentBuildError, match="finding template requires checks from an unassociated playbook"
    ):
        _validate_cross_references({}, (topic,), _valid_cues(), (), (), (template,), (), ())
    with pytest.raises(
        ValueError, match="finding template requires checks from an unassociated playbook"
    ):
        ContentCatalog(
            _seed_provenance(),
            CueCatalog(version="1", sha256="0" * 64, cues=[], aliases=[], ambiguities=[]),
            (topic,),
            (),
            templates=(template,),
        )


def test_declared_prerequisite_passes_build_and_loaded_catalog() -> None:
    topic = _ldap_topic(playbook_id="ldap_checks")
    playbook = _declared_check_playbook(declared=("ldap_alert_count",))
    template = _prerequisite_template(check_id="ldap_alert_count")
    _validate_cross_references({}, (topic,), _valid_cues(), (playbook,), (), (template,), (), ())
    catalog = ContentCatalog(
        _seed_provenance(),
        CueCatalog(version="1", sha256="0" * 64, cues=[], aliases=[], ambiguities=[]),
        (topic,),
        (),
        (playbook,),
        (),
        (template,),
    )
    assert [item.template_id for item in catalog.finding_templates("ldap")] == ["ldap_visible"]


def test_duplicate_required_playbook_check_declarations_fail_build_and_constructor() -> None:
    topic = _ldap_topic(playbook_id="ldap_checks")
    playbook = _declared_check_playbook(declared=("ldap_alert_count", "ldap_alert_count"))
    template = _prerequisite_template(check_id="ldap_alert_count")

    with pytest.raises(ContentBuildError, match="duplicate playbook output ID"):
        _validate_cross_references(
            {}, (topic,), _valid_cues(), (playbook,), (), (template,), (), ()
        )
    with pytest.raises(ValueError, match="duplicated playbook check"):
        ContentCatalog(
            _seed_provenance(),
            CueCatalog(version="1", sha256="0" * 64, cues=[], aliases=[], ambiguities=[]),
            (topic,),
            (),
            (playbook,),
            (),
            (template,),
        )


@pytest.mark.parametrize("second_declared", [("shadow_check",), ("real_check",)])
def test_loaded_catalog_rejects_duplicate_playbook_authority_before_reference_lookup(
    second_declared: tuple[str, ...],
) -> None:
    first = _declared_check_playbook(declared=("real_check",))
    second = _declared_check_playbook(declared=second_declared)
    topic = _ldap_topic(playbook_id="ldap_checks")
    template = _prerequisite_template(check_id="shadow_check")

    with pytest.raises(ContentBuildError, match="duplicate playbook IDs"):
        _validate_cross_references(
            {}, (topic,), _valid_cues(), (first, second), (), (template,), (), ()
        )
    with pytest.raises(ValueError, match="duplicate approved playbook IDs"):
        ContentCatalog(
            _seed_provenance(),
            CueCatalog(version="1", sha256="0" * 64, cues=[], aliases=[], ambiguities=[]),
            (topic,),
            (),
            (first, second),
            (),
            (template,),
        )


def test_duplicate_prerequisite_declaration_is_rejected() -> None:
    template = FindingTemplate(
        template_id="ldap_visible",
        topic_id="ldap",
        kind="observation",
        required_bindings={"count": ("count",)},
        texts=LocaleText(
            en="Observed {count} visible objects",
            es="Se observaron {count} objetos visibles",
        ),
        required_check_outcomes=[
            RequiredCheckOutcome(check_id="ldap_alert_count", outcome=CheckOutcome.passed),
            RequiredCheckOutcome(check_id="ldap_alert_count", outcome=CheckOutcome.passed),
        ],
        allowed_evidence_kinds=["aggregate"],
    )
    with pytest.raises(
        ContentBuildError, match="finding template declares a duplicate check prerequisite"
    ):
        _validate_finding_templates((template,))


def _recency_playbook(
    *,
    extra_checks: tuple[str, ...] = (),
    age_fetch: str = "alerts",
    template_id: TemplateId = TemplateId.alerts_rows_v1,
) -> PlaybookDefinition:
    label = LocaleText(en="recency", es="recencia")
    return PlaybookDefinition(
        playbook_id="ldap_checks",
        topic_id="ldap",
        title=label,
        internal_context="fixture",
        steps=[
            FetchStep(
                kind="fetch",
                step_id="alerts_fetch",
                label=label,
                fetch_id="alerts",
                template_id=template_id,
                window_default={"unit": "hours", "amount": 24},
                filters=[],
            ),
            RecordAgeStep(
                kind="record_age",
                step_id="alerts_recency",
                check_id="ldap_recency",
                label=label,
                fetch_id=age_fetch,
                max_age_seconds=300,
            ),
            *(
                CompareCountStep(
                    kind="compare_count",
                    step_id=f"count_compare_{index}",
                    label=label,
                    check_id=check_id,
                    left_fetch_id="alerts",
                    op="gte",
                    right=IntegerOperand(kind="literal", value=0),
                )
                for index, check_id in enumerate(extra_checks)
            ),
        ],
    )


def _recency_template(**update: object) -> FindingTemplate:
    template = FindingTemplate(
        template_id="ldap_recency_gap",
        topic_id="ldap",
        kind="observation",
        required_bindings={"result": ("outcome",)},
        texts=LocaleText(
            en=(
                "The newest returned record with a valid timestamp inside the read window "
                "is older than the limit: {result}"
            ),
            es=(
                "El registro devuelto mas reciente con una marca de tiempo valida dentro de "
                "la ventana de lectura supera el limite: {result}"
            ),
        ),
        required_check_outcomes=[
            RequiredCheckOutcome(check_id="ldap_recency", outcome=CheckOutcome.failed)
        ],
        allowed_evidence_kinds=["check"],
    )
    return template.model_copy(update=update) if update else template


def _validate_recency(playbook: PlaybookDefinition, template: FindingTemplate) -> None:
    topic = _ldap_topic(playbook_id="ldap_checks")
    _validate_cross_references({}, (topic,), _valid_cues(), (playbook,), (), (template,), (), ())


def test_record_age_disclosure_shape_builds_at_build_and_loaded_catalog() -> None:
    topic = _ldap_topic(playbook_id="ldap_checks")
    playbook = _recency_playbook()
    template = _recency_template()
    _validate_recency(playbook, template)
    catalog = ContentCatalog(
        _seed_provenance(),
        CueCatalog(version="1", sha256="0" * 64, cues=[], aliases=[], ambiguities=[]),
        (topic,),
        (),
        (playbook,),
        (),
        (template,),
    )
    assert [item.template_id for item in catalog.finding_templates("ldap")] == ["ldap_recency_gap"]


@pytest.mark.parametrize(
    ("template", "playbook", "message"),
    [
        (
            _recency_template(
                required_check_outcomes=[
                    RequiredCheckOutcome(check_id="ldap_recency", outcome=CheckOutcome.passed)
                ]
            ),
            _recency_playbook(),
            "record_age check outside the failed disclosure shape",
        ),
        (
            _recency_template(kind="hypothesis"),
            _recency_playbook(),
            "record_age check outside the failed disclosure shape",
        ),
        (
            _recency_template(allowed_evidence_kinds=["row"]),
            _recency_playbook(),
            "record_age check outside the failed disclosure shape",
        ),
        (
            _recency_template(allowed_evidence_kinds=["check", "row"]),
            _recency_playbook(),
            "record_age check outside the failed disclosure shape",
        ),
        (
            _recency_template(
                required_bindings={"result": ("outcome",), "other": ("outcome",)},
                texts=LocaleText(
                    en="Recency {result} {other}",
                    es="Recencia {result} {other}",
                ),
            ),
            _recency_playbook(),
            "record_age check outside the failed disclosure shape",
        ),
        (
            _recency_template(
                required_check_outcomes=[
                    RequiredCheckOutcome(check_id="ldap_alert_count", outcome=CheckOutcome.passed),
                    RequiredCheckOutcome(check_id="ldap_recency", outcome=CheckOutcome.failed),
                ]
            ),
            _recency_playbook(extra_checks=("ldap_alert_count",)),
            "record_age check outside the failed disclosure shape",
        ),
    ],
    ids=[
        "passed-outcome",
        "hypothesis-kind",
        "row-only-evidence",
        "mixed-row-and-check",
        "two-bindings",
        "vuln-style-second-prerequisite",
    ],
)
def test_forbidden_record_age_citation_shapes_fail_build(template, playbook, message) -> None:
    with pytest.raises(ContentBuildError, match=message):
        _validate_recency(playbook, template)


def test_check_evidence_without_prerequisite_fails_build_and_loaded_catalog() -> None:
    topic = _ldap_topic(playbook_id="ldap_checks")
    playbook = _recency_playbook()
    template = _recency_template(
        required_check_outcomes=[], allowed_evidence_kinds=["row", "check"]
    )
    with pytest.raises(ContentBuildError, match="allows check evidence without a prerequisite"):
        _validate_cross_references(
            {}, (topic,), _valid_cues(), (playbook,), (), (template,), (), ()
        )
    with pytest.raises(ValueError, match="allows check evidence without a prerequisite"):
        ContentCatalog(
            _seed_provenance(),
            CueCatalog(version="1", sha256="0" * 64, cues=[], aliases=[], ambiguities=[]),
            (topic,),
            (),
            (playbook,),
            (),
            (template,),
        )


@pytest.mark.parametrize("age_fetch", ["missing", "later"])
def test_record_age_must_reference_an_earlier_fetch(age_fetch: str) -> None:
    playbook = _recency_playbook(age_fetch=age_fetch)
    if age_fetch == "later":
        playbook = playbook.model_copy(
            update={
                "steps": [
                    playbook.steps[1],
                    playbook.steps[0],
                ]
            }
        )
    with pytest.raises(ContentBuildError, match="forward or unknown fetch reference"):
        _validate_recency(playbook, _recency_template())


@pytest.mark.parametrize(
    "playbook",
    [
        _recency_playbook(age_fetch="missing"),
        _recency_playbook().model_copy(
            update={
                "steps": [
                    _recency_playbook().steps[1],
                    _recency_playbook().steps[0],
                ]
            }
        ),
    ],
    ids=["missing-fetch", "forward-fetch"],
)
def test_loaded_catalog_rejects_missing_and_forward_record_age_fetches(playbook) -> None:
    with pytest.raises(ValueError, match="forward or unknown fetch reference"):
        ContentCatalog(
            _seed_provenance(),
            CueCatalog(version="1", sha256="0" * 64, cues=[], aliases=[], ambiguities=[]),
            (_ldap_topic(playbook_id="ldap_checks"),),
            (),
            (playbook,),
        )


@pytest.mark.parametrize("template_id", [TemplateId.alerts_count_v1, TemplateId.alerts_group_v1])
def test_record_age_must_read_a_rows_template(template_id) -> None:
    playbook = _recency_playbook(template_id=template_id)
    with pytest.raises(ContentBuildError, match="record_age step must read a rows template"):
        _validate_recency(playbook, _recency_template())


@pytest.mark.parametrize(
    "template_id",
    [TemplateId.alerts_count_v1, TemplateId.alerts_group_v1],
    ids=["count-template", "group-template"],
)
def test_loaded_catalog_rejects_record_age_count_and_group_fetches(template_id) -> None:
    playbook = _recency_playbook(template_id=template_id)
    with pytest.raises(ValueError, match="record_age step must read a rows template"):
        ContentCatalog(
            _seed_provenance(),
            CueCatalog(version="1", sha256="0" * 64, cues=[], aliases=[], ambiguities=[]),
            (_ldap_topic(playbook_id="ldap_checks"),),
            (),
            (playbook,),
        )
