import hashlib
import json

import pytest

from ai_soc.content.builder import (
    ContentBuildError,
    _topic_card_texts,
    _TopicCardVector,
    _validate_topic_cards,
    load_topic_card_vectors,
)
from ai_soc.contracts.canonical import canonical_bytes
from ai_soc.contracts.models import EmbeddingManifest, PackManifest, TopicDefinition


def test_topic_card_manifest_binds_bilingual_text_vector_and_empty_goldens() -> None:
    topic = TopicDefinition(
        topic_id="ldap",
        name={"en": "LDAP", "es": "LDAP"},
        aliases=[],
        public_document=None,
        playbook_id=None,
        finding_template_ids=[],
        fetch_bindings=[],
    )
    topics = (topic,)
    vectors = (_TopicCardVector(schema_version="1", topic_id="ldap", vector=[1.0, 0.0]),)
    corpus_sha = hashlib.sha256(canonical_bytes(_topic_card_texts(topics))).hexdigest()
    vector_sha = hashlib.sha256(canonical_bytes({"ldap": [1.0, 0.0]})).hexdigest()
    golden_sha = hashlib.sha256(canonical_bytes([])).hexdigest()
    manifest = EmbeddingManifest(
        model_id="fixture-embedding",
        region="us-east-1",
        dimensions=2,
        purpose="topic_cards",
        normalization="l2",
        corpus_sha256=corpus_sha,
        vector_sha256=vector_sha,
        golden_sha256=golden_sha,
        threshold=0.8,
        minimum_margin=0.1,
        selection_report_path="reports/selection.json",
    )
    _validate_topic_cards(manifest, topics, vectors, ())
    with pytest.raises(ContentBuildError, match="L2 normalized"):
        _validate_topic_cards(
            manifest.model_copy(
                update={
                    "vector_sha256": hashlib.sha256(
                        canonical_bytes({"ldap": [2.0, 0.0]})
                    ).hexdigest()
                }
            ),
            topics,
            (_TopicCardVector(schema_version="1", topic_id="ldap", vector=[2.0, 0.0]),),
            (),
        )


def test_topic_vector_loader_rejects_incompatible_hash_and_topic_inventory(
    tmp_path, monkeypatch
) -> None:
    topic = TopicDefinition(
        topic_id="ldap",
        name={"en": "LDAP", "es": "LDAP"},
        aliases=[],
        public_document=None,
        playbook_id=None,
        finding_template_ids=[],
        fetch_bindings=[],
    )
    vector = [1.0, 0.0]
    vector_sha = hashlib.sha256(canonical_bytes({"ldap": vector})).hexdigest()
    embedding = EmbeddingManifest(
        model_id="fixture-embedding",
        region="us-east-1",
        dimensions=2,
        purpose="topic_cards",
        normalization="l2",
        corpus_sha256="1" * 64,
        vector_sha256=vector_sha,
        golden_sha256="2" * 64,
        threshold=0.8,
        minimum_margin=0.1,
        selection_report_path="reports/selection.json",
    )
    pack_manifest = PackManifest(
        source_repository="https://example.test/content",
        content_sha="3" * 40,
        source_tree_sha256="4" * 64,
        pack_sha256="5" * 64,
        docs_manifest_sha256="6" * 64,
        cue_pack_sha="7" * 64,
        review_attestation="https://example.test/reviews/1",
        files=[],
        embedding=embedding,
    )
    (tmp_path / "pack/topics").mkdir(parents=True)
    (tmp_path / "pack/topic-cards").mkdir(parents=True)
    (tmp_path / "manifest.json").write_text(pack_manifest.model_dump_json(), encoding="utf-8")
    (tmp_path / "pack/topics/ldap.json").write_text(topic.model_dump_json(), encoding="utf-8")
    card = {
        "schema_version": "1",
        "topic_id": "ldap",
        "text_en": "LDAP",
        "text_es": "LDAP",
        "vector": vector,
    }
    (tmp_path / "pack/topic-cards/ldap.json").write_text(json.dumps(card), encoding="utf-8")
    monkeypatch.setattr("ai_soc.content.builder.verify_content_pack", lambda _pack: None)

    assert dict(load_topic_card_vectors(tmp_path)) == {"ldap": (1.0, 0.0)}
    wrong_hash = pack_manifest.model_copy(
        update={"embedding": embedding.model_copy(update={"vector_sha256": "8" * 64})}
    )
    (tmp_path / "manifest.json").write_text(wrong_hash.model_dump_json(), encoding="utf-8")
    with pytest.raises(ContentBuildError, match="vector hash"):
        load_topic_card_vectors(tmp_path)

    (tmp_path / "manifest.json").write_text(pack_manifest.model_dump_json(), encoding="utf-8")
    (tmp_path / "pack/topic-cards/other.json").write_text(
        json.dumps({**card, "topic_id": "other"}), encoding="utf-8"
    )
    with pytest.raises(ContentBuildError, match="do not match packed topics"):
        load_topic_card_vectors(tmp_path)
