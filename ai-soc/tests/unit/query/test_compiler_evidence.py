from __future__ import annotations

import hashlib
import json
from pathlib import Path
from uuid import UUID

import pytest

from ai_soc.contracts.models import (
    Count,
    FieldId,
    Filter,
    GroupField,
    SnapshotKind,
    SnapshotRef,
    TemplateId,
    Visibility,
)
from ai_soc.query.compiler import QueryCompileError, compile_fetch
from ai_soc.query.evidence import (
    build_empty_proof,
    count_item,
    materialize_rows,
    row_item,
    snapshot_ref,
)


def test_compiler_uses_finite_template_and_half_open_time_window(site, fetch, mapping_profile):
    config, authorized = site
    compiled = compile_fetch(fetch, authorized, mapping_profile)
    assert compiled.path == "/wazuh-alerts-alpha-*/_search"
    filters = compiled.body["query"]["bool"]["filter"]
    assert filters[0]["range"]["@timestamp"] == {
        "gte": fetch.window.start.isoformat().replace("+00:00", "Z"),
        "lt": fetch.window.end.isoformat().replace("+00:00", "Z"),
    }
    assert filters[1] == {"term": {"agent.id": "007"}}
    assert compiled.body["size"] == 2
    assert compiled.body["_source"]
    assert compiled.body["sort"] == [
        {"@timestamp": {"order": "desc"}},
        {"_index": {"order": "desc"}},
        {"_id": {"order": "desc"}},
    ]
    assert config.environment_id == "alpha"


def test_filter_payload_is_a_literal_and_cannot_inject_dsl(site, fetch, mapping_profile):
    _, authorized = site
    hostile = fetch.model_copy(
        update={"filters": [Filter(field=FieldId.agent_name, op="eq", value='alice"} OR *:* #')]}
    )
    compiled = compile_fetch(hostile, authorized, mapping_profile)
    clause = compiled.body["query"]["bool"]["filter"][1]
    assert clause == {"term": {"agent.name": 'alice"} OR *:* #'}}
    assert "script" not in repr(compiled.body)
    assert "raw_query" not in repr(compiled.body)


def test_compiler_rejects_non_site_template_mapping_or_index(site, fetch, mapping_profile):
    config, authorized = site
    disallowed_config = config.model_copy(update={"allowed_templates": ()})
    disallowed = authorized.model_copy(update={"config": disallowed_config})
    with pytest.raises(QueryCompileError):
        compile_fetch(fetch, disallowed, mapping_profile)
    bad_profile = mapping_profile.__class__(
        profile_id="wrong-profile",
        fields=mapping_profile.fields,
        alert_projection=mapping_profile.alert_projection,
        vulnerability_projection=mapping_profile.vulnerability_projection,
        tie_break_field="_id",
    )
    with pytest.raises(QueryCompileError):
        compile_fetch(fetch, authorized, bad_profile)
    bad_config = config.model_copy(update={"allowed_index_patterns": {}})
    with pytest.raises(QueryCompileError):
        compile_fetch(fetch, authorized.model_copy(update={"config": bad_config}), mapping_profile)


def test_golden_english_fetch_example_compiles_with_its_frozen_filter(site, fetch, mapping_profile):
    fixture_path = Path(__file__).parents[2] / "fixtures/v1/golden_examples.json"
    fixture_bytes = fixture_path.read_bytes()
    fixture_sha256 = hashlib.sha256(fixture_bytes).hexdigest()
    assert fixture_sha256 == "2e4e06a11dd92d169e25791db83e7e16d8ed8777081666b5fa83b1ec3ab2ed5d"
    cases = json.loads(fixture_bytes)["cases"]
    case = next(item for item in cases if item["case_id"] == "G003.en.fetch")
    assert case["fixture_sha256"] == (
        "e6d52fe71a2af38a1ec7b6ff8365237e5ae1e9e0761c42fb0822afeaca661977"
    )
    expected = case["expected"]["payload"]["topic_plans"][0]
    _, authorized = site
    compiled = compile_fetch(
        fetch.model_copy(
            update={
                "template_id": TemplateId(expected["fetch_templates"][0]),
                "filters": [
                    Filter(
                        field=FieldId.agent_id,
                        op="eq",
                        value=expected["filter_agent_id"],
                    )
                ],
            }
        ),
        authorized,
        mapping_profile,
    )
    assert compiled.path == "/wazuh-alerts-alpha-*/_search"
    assert compiled.body["query"]["bool"]["filter"][1] == {"term": {"agent.id": "007"}}


@pytest.mark.parametrize("variant", ["positive", "negative", "boundary", "failure"])
def test_finite_query_compiler_security_and_window_cases(
    site, fetch, mapping_profile, variant, request
):
    fixture_path = Path(__file__).parent / "data/g003_compiler_cases.json"
    fixture_bytes = fixture_path.read_bytes()
    fixture_sha256 = hashlib.sha256(fixture_bytes).hexdigest()
    assert fixture_sha256 == "8ed7069e4826fb38c3965b88110a8b3d1223b3499e29d5232d65702723e6b1c4"
    scenario = json.loads(fixture_bytes)["variants"][variant]
    _, authorized = site
    request.node.user_properties.extend(
        [
            ("acceptance_ids", "G003"),
            ("case_id", "B3-G003.compiler"),
            ("variant", variant),
            ("fixture_sha256", fixture_sha256),
        ]
    )

    if variant == "failure":
        denied_config = authorized.config.model_copy(update={"allowed_templates": ()})
        with pytest.raises(QueryCompileError):
            compile_fetch(
                fetch,
                authorized.model_copy(update={"config": denied_config}),
                mapping_profile,
            )
        return

    request_fetch = fetch.model_copy(
        update={
            "template_id": TemplateId(scenario.get("template_id", fetch.template_id)),
            "filters": [
                Filter(
                    field=FieldId.agent_id,
                    op="eq",
                    value=scenario.get("filter_value", "007"),
                )
            ],
        }
    )
    compiled = compile_fetch(request_fetch, authorized, mapping_profile)
    filters = compiled.body["query"]["bool"]["filter"]
    if variant == "boundary":
        assert scenario["window"] == "[start,end)"
        assert filters[0]["range"]["@timestamp"]["gte"].endswith("Z")
        assert filters[0]["range"]["@timestamp"]["lt"].endswith("Z")
    elif variant == "negative":
        literal = scenario["filter_value"]
        assert filters[1] == {"term": {"agent.id": literal}}
        assert "script" not in repr(compiled.body)
        assert "raw_query" not in repr(compiled.body)
    else:
        assert filters[1] == {"term": {"agent.id": scenario["filter_value"]}}


def test_canonical_row_vector_matches_independent_frozen_id(site, fetch):
    _, authorized = site
    canonical_fetch = fetch.model_copy(update={"fetch_id": "ldap_rows"})
    snapshot = SnapshotRef(
        kind=SnapshotKind.pit,
        key="1" * 64,
        at=fetch.window.anchor_at,
    )
    _, item = row_item(
        question_id=UUID("00000000-0000-4000-8000-000000000001"),
        environment_id="alpha",
        topic_id="ldap",
        fetch=canonical_fetch,
        snapshot=snapshot,
        visibility=Visibility.full,
        policy_hash=authorized.policy_hash,
        index_alias="alerts",
        record_id="alpha-ldap-001",
        values={FieldId.agent_id: "007", FieldId.rule_id: "5710", FieldId.data_srcip: "192.0.2.10"},
    )
    assert (
        item.evidence_id == "ev1_f9ebaeca124728503e65d2bdb0bec734345aa92a2978a0f4b32af4726006a796"
    )


def test_evidence_keeps_zero_and_count_only_positive_distinct(site, fetch):
    _, authorized = site
    snapshot = snapshot_ref(
        environment_id="alpha",
        pit_id=None,
        question_id=UUID("00000000-0000-0000-0000-000000000001"),
        fetch=fetch,
        at=fetch.window.anchor_at,
        response_identity="empty-response",
    )
    zero = Count(value=0, relation="eq", scope="matching_visible_records", computed_by="indexer")
    positive = Count(
        value=2, relation="eq", scope="matching_visible_records", computed_by="indexer"
    )
    zero_item = count_item(
        question_id=UUID("00000000-0000-0000-0000-000000000001"),
        environment_id="alpha",
        topic_id="ldap",
        fetch=fetch,
        snapshot=snapshot,
        visibility=Visibility.full,
        policy_hash=authorized.policy_hash,
        count=zero,
    )
    positive_item = count_item(
        question_id=UUID("00000000-0000-0000-0000-000000000001"),
        environment_id="alpha",
        topic_id="ldap",
        fetch=fetch,
        snapshot=snapshot,
        visibility=Visibility.full,
        policy_hash=authorized.policy_hash,
        count=positive,
    )
    assert zero_item.evidence_id != positive_item.evidence_id
    assert zero_item.values["count"] == 0
    assert positive_item.values["count"] == 2
    count_fetch = fetch.model_copy(
        update={"fetch_id": "ldap_count", "template_id": TemplateId.alerts_count_v1, "filters": []}
    )
    canonical_count = count_item(
        question_id=UUID("00000000-0000-4000-8000-000000000001"),
        environment_id="alpha",
        topic_id="ldap",
        fetch=count_fetch,
        snapshot=SnapshotRef(
            kind=SnapshotKind.pit,
            key="1" * 64,
            at=fetch.window.anchor_at,
        ),
        visibility=Visibility.full,
        policy_hash=authorized.policy_hash,
        count=positive,
    )
    assert (
        canonical_count.evidence_id
        == "ev1_9f9ffe241e8218ea90144a45cda4ebb8a5d317236d07b176f98ff45d60938fec"
    )
    proof = build_empty_proof(
        question_id=UUID("00000000-0000-0000-0000-000000000001"),
        environment_id="alpha",
        topic_id="ldap",
        fetch=fetch,
        snapshot=snapshot,
        visibility=Visibility.full,
        policy_hash=authorized.policy_hash,
        index_exists=True,
        window_count=positive,
        filter_counts=[(fetch.filters[0], zero)],
        combination_count=zero,
    )
    assert proof.consistency == "unconfirmed"  # first page cannot prove a coherent empty
    assert proof.matched_nothing == [FieldId.agent_id]
    coherent_snapshot = SnapshotRef(kind=SnapshotKind.pit, key="2" * 64, at=fetch.window.anchor_at)
    coherent = build_empty_proof(
        question_id=UUID("00000000-0000-0000-0000-000000000001"),
        environment_id="alpha",
        topic_id="ldap",
        fetch=fetch,
        snapshot=coherent_snapshot,
        visibility=Visibility.full,
        policy_hash=authorized.policy_hash,
        index_exists=True,
        window_count=positive,
        filter_counts=[(fetch.filters[0], positive)],
        combination_count=zero,
    )
    assert coherent.consistency == "coherent"


@pytest.mark.parametrize(
    ("first_level", "second_level", "second_agent_name", "conflicting"),
    [
        pytest.param(5, 5, "different", True, id="distinct-agent-name"),
        pytest.param(1, True, "alpha-agent", True, id="integer-then-boolean-level"),
        pytest.param(True, 1, "alpha-agent", True, id="boolean-then-integer-level"),
        pytest.param(0, False, "alpha-agent", True, id="zero-then-false-level"),
        pytest.param(False, 0, "alpha-agent", True, id="false-then-zero-level"),
        pytest.param(True, True, "alpha-agent", False, id="identical-boolean-level"),
        pytest.param(1, 1, "alpha-agent", False, id="identical-integer-level"),
    ],
)
def test_evidence_materialization_rejects_conflicting_duplicate_record(
    site, fetch, first_level, second_level, second_agent_name, conflicting
):
    _, authorized = site
    from ai_soc.query.compiler import default_profile

    profile = default_profile()
    snapshot = snapshot_ref(
        environment_id="alpha",
        pit_id="pit-1",
        question_id=UUID("00000000-0000-0000-0000-000000000001"),
        fetch=fetch,
        at=fetch.window.anchor_at,
    )
    hit = {
        "_index": "wazuh-alerts-alpha-2026.09.30",
        "_id": "same",
        "_source": {
            "@timestamp": "2026-09-30T11:00:00Z",
            "agent": {"id": "007", "name": "alpha-agent"},
            "rule": {"id": "5710", "level": first_level, "groups": ["auth"]},
            "data": {"srcip": "192.0.2.7", "dstip": "192.0.2.8"},
        },
    }
    repeated = {
        **hit,
        "_source": {
            **hit["_source"],
            "agent": {"id": "007", "name": second_agent_name},
            "rule": {"id": "5710", "level": second_level, "groups": ["auth"]},
        },
    }
    if conflicting:
        with pytest.raises(ValueError, match="conflicting duplicate"):
            materialize_rows(
                hits=[hit, repeated],
                fields=profile.alert_projection,
                field_names=profile.fields,
                question_id=UUID("00000000-0000-0000-0000-000000000001"),
                environment_id="alpha",
                topic_id="ldap",
                fetch=fetch,
                snapshot=snapshot,
                visibility=Visibility.full,
                policy_hash=authorized.policy_hash,
            )
        return
    columns, rows, items = materialize_rows(
        hits=[hit, repeated],
        fields=profile.alert_projection,
        field_names=profile.fields,
        question_id=UUID("00000000-0000-0000-0000-000000000001"),
        environment_id="alpha",
        topic_id="ldap",
        fetch=fetch,
        snapshot=snapshot,
        visibility=Visibility.full,
        policy_hash=authorized.policy_hash,
    )
    assert columns
    assert len(rows) == 1
    assert len(items) == 1
    assert rows[0].values[FieldId.rule_level] is first_level


def test_evidence_materialization_keys_sources_by_index_and_id(site, fetch):
    _, authorized = site
    from ai_soc.query.compiler import default_profile

    profile = default_profile()
    snapshot = snapshot_ref(
        environment_id="alpha",
        pit_id="pit-1",
        question_id=UUID("00000000-0000-0000-0000-000000000001"),
        fetch=fetch,
        at=fetch.window.anchor_at,
    )
    source = {
        "@timestamp": "2026-09-30T11:00:00Z",
        "agent": {"id": "007", "name": "alpha-agent"},
        "rule": {"id": "5710", "level": 5, "groups": ["auth"]},
        "data": {"srcip": "192.0.2.7", "dstip": "192.0.2.8"},
    }
    first = {"_index": "wazuh-alerts-alpha-a", "_id": "same", "_source": source}
    same_source_repeat = {**first, "_source": dict(source)}
    reused_id = {"_index": "wazuh-alerts-alpha-b", "_id": "same", "_source": source}
    columns, rows, items = materialize_rows(
        hits=[first, same_source_repeat, reused_id],
        fields=profile.alert_projection,
        field_names=profile.fields,
        question_id=UUID("00000000-0000-0000-0000-000000000001"),
        environment_id="alpha",
        topic_id="ldap",
        fetch=fetch,
        snapshot=snapshot,
        visibility=Visibility.full,
        policy_hash=authorized.policy_hash,
    )
    assert columns
    assert [row.record_ref.index_alias for row in rows] == [
        "wazuh-alerts-alpha-a",
        "wazuh-alerts-alpha-b",
    ]
    assert [row.record_ref.record_id for row in rows] == ["same", "same"]
    assert len({item.evidence_id for item in items}) == 2
    assert [item.source.index_alias for item in items] == [
        "wazuh-alerts-alpha-a",
        "wazuh-alerts-alpha-b",
    ]


@pytest.mark.parametrize("variant", ["positive", "negative", "boundary", "failure"])
def test_frozen_canonical_evidence_vectors_and_conflict_rejection(site, fetch, variant, request):
    fixture_path = Path(__file__).parents[2] / "fixtures/v1/canonical_vectors.json"
    fixture_bytes = fixture_path.read_bytes()
    fixture_sha256 = hashlib.sha256(fixture_bytes).hexdigest()
    assert fixture_sha256 == "4ee012d1c092d192baae112559b02f774d7300d879e7615e56d441f5972d4cbb"
    vectors = json.loads(fixture_bytes)
    page = next(vector for vector in vectors["vectors"] if vector["name"] == "page-one")
    canonical = page["canonical_input"]
    _, authorized = site
    canonical_fetch = fetch.model_copy(update={"fetch_id": canonical["fetch_id"]})
    snapshot_key = canonical["snapshot_key"]
    if variant == "negative":
        snapshot_key = "2" * 64
    snapshot = SnapshotRef(
        kind=SnapshotKind.pit,
        key=snapshot_key,
        at=fetch.window.anchor_at,
    )
    values = {FieldId(key): value for key, value in canonical["values"].items()}
    if variant == "boundary":
        values = dict(reversed(tuple(values.items())))
    request.node.user_properties.extend(
        [
            ("acceptance_ids", "G038,G059"),
            ("case_id", "SEC-002.resolution"),
            ("variant", variant),
            ("fixture_sha256", fixture_sha256),
        ]
    )

    if variant == "failure":
        from ai_soc.query.compiler import default_profile

        profile = default_profile("wazuh-v4-fixture")
        hit = {
            "_index": "wazuh-alerts-alpha-2026.09.30",
            "_id": canonical["source"]["record_id"],
            "_source": {
                "@timestamp": "2026-09-30T11:00:00Z",
                "agent": {"id": "007", "name": "alpha-agent"},
                "rule": {"id": "5710", "level": 5, "groups": ["auth"]},
                "data": {"srcip": "192.0.2.10", "dstip": "192.0.2.8"},
            },
        }
        conflicting = {
            **hit,
            "_source": {**hit["_source"], "agent": {"id": "007", "name": "changed"}},
        }
        with pytest.raises(ValueError, match="conflicting duplicate"):
            materialize_rows(
                hits=[hit, conflicting],
                fields=profile.alert_projection,
                field_names=profile.fields,
                question_id=UUID(canonical["question_id"]),
                environment_id=canonical["environment_id"],
                topic_id=canonical["topic_id"],
                fetch=canonical_fetch,
                snapshot=snapshot,
                visibility=Visibility.full,
                policy_hash=authorized.policy_hash,
            )
        return

    _, item = row_item(
        question_id=UUID(canonical["question_id"]),
        environment_id=canonical["environment_id"],
        topic_id=canonical["topic_id"],
        fetch=canonical_fetch,
        snapshot=snapshot,
        visibility=Visibility.full,
        policy_hash=authorized.policy_hash,
        index_alias=canonical["source"]["index_alias"],
        record_id=canonical["source"]["record_id"],
        values=values,
    )
    if variant == "negative":
        assert item.evidence_id != page["expected_evidence_id"]
    else:
        assert item.evidence_id == page["expected_evidence_id"]


@pytest.mark.parametrize("variant", ["positive", "negative", "boundary", "failure"])
def test_empty_proof_requires_coherent_same_pit_visible_diagnostics(site, fetch, variant, request):
    fixture_path = Path(__file__).parents[2] / "fixtures/v1/canonical_vectors.json"
    fixture_bytes = fixture_path.read_bytes()
    fixture_sha256 = hashlib.sha256(fixture_bytes).hexdigest()
    assert fixture_sha256 == "4ee012d1c092d192baae112559b02f774d7300d879e7615e56d441f5972d4cbb"
    vectors = json.loads(fixture_bytes)["vectors"]
    zero_value = vectors[0]["canonical_input"]["values"]["count"]
    positive_value = 2
    _, authorized = site
    snapshot = SnapshotRef(
        kind=SnapshotKind.first_page_only if variant == "boundary" else SnapshotKind.pit,
        key="1" * 64,
        at=fetch.window.anchor_at,
    )
    request.node.user_properties.extend(
        [
            ("acceptance_ids", "G051"),
            ("case_id", "ARCH-010.resolution"),
            ("variant", variant),
            ("fixture_sha256", fixture_sha256),
        ]
    )

    def count(value):
        return Count(
            value=value,
            relation="eq",
            scope="matching_visible_records",
            computed_by="indexer",
        )

    if variant == "failure":
        proof = build_empty_proof(
            question_id=UUID("00000000-0000-4000-8000-000000000001"),
            environment_id="alpha",
            topic_id="ldap",
            fetch=fetch,
            snapshot=snapshot,
            visibility=Visibility.full,
            policy_hash=authorized.policy_hash,
            index_exists=None,
            window_count=None,
            filter_counts=[(fetch.filters[0], None)],
            combination_count=None,
        )
        assert proof.consistency == "unconfirmed"
        assert proof.filter_probes[0].outcome == "unknown"
        return

    proof = build_empty_proof(
        question_id=UUID("00000000-0000-4000-8000-000000000001"),
        environment_id="alpha",
        topic_id="ldap",
        fetch=fetch,
        snapshot=snapshot,
        visibility=Visibility.filtered if variant == "negative" else Visibility.full,
        policy_hash=authorized.policy_hash,
        index_exists=True,
        window_count=count(positive_value),
        filter_counts=[(fetch.filters[0], count(zero_value))],
        combination_count=count(zero_value),
    )
    if variant == "positive":
        assert proof.consistency == "coherent"
        assert proof.matched_nothing == [FieldId.agent_id]
    elif variant == "negative":
        assert proof.consistency == "unconfirmed"
        assert proof.visibility == Visibility.filtered
        assert proof.matched_nothing == [FieldId.agent_id]
    else:
        assert proof.consistency == "unconfirmed"


def test_unknown_composite_visibility_still_compiles_fetch(site, fetch, mapping_profile):
    _, authorized = site
    unknown_site = authorized.model_copy(update={"visibility": Visibility.unknown})
    compiled = compile_fetch(fetch, unknown_site, mapping_profile)
    assert compiled.body["sort"][0]["@timestamp"]["order"] == "desc"


def test_group_terms_aggregation_uses_twenty_bucket_limit(site, fetch, mapping_profile):
    _, authorized = site
    grouped = fetch.model_copy(
        update={
            "template_id": TemplateId.alerts_group_v1,
            "group_by": GroupField.agent_id,
        }
    )
    compiled = compile_fetch(grouped, authorized, mapping_profile)
    terms = compiled.body["aggs"]["visible_groups"]["terms"]
    assert terms["size"] == 20
