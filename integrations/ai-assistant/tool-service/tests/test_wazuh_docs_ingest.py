"""Unit tests for D60 Wazuh docs ingest helpers (no network)."""
from __future__ import annotations

from app.docs_kb_text import (
    canonical_html,
    chunk_markdown,
    parse_llms_entries,
    pin_url,
)


def test_parse_llms_and_pin_url():
    sample = """
- **[Active Response](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.md)** Automate.
- **[FIM](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.md)** Files.
"""
    entries = parse_llms_entries(sample)
    assert len(entries) == 2
    assert entries[0][0] == "Active Response"
    pinned = pin_url(entries[0][1], "4.14")
    assert "/4.14/" in pinned
    assert canonical_html(pinned).endswith(".html")


def test_chunk_markdown_heading_aware():
    md = """# Active Response

Intro paragraph about AR.

## Types of active response

Stateless and stateful responses.

### Stateless

One-time actions.
"""
    docs = chunk_markdown(
        "Active Response",
        "https://documentation.wazuh.com/4.14/user-manual/capabilities/active-response/index.html",
        md,
    )
    assert docs
    assert all(d["id"].startswith("doc-") for d in docs)
    assert all(d["url"].endswith(".html") for d in docs)
    assert any("Stateless" in d["section"] or "Stateless" in d["text"] for d in docs)


def test_docs_corpus_file_loads_when_present():
    from app.knowledge import corpus_ids, reload_corpora

    reload_corpora()
    ids = corpus_ids()
    # Hand corpus always present; docs corpus present after make docs-kb.
    assert "kb-ssh-bruteforce" in ids
    doc_ids = [i for i in ids if i.startswith("doc-")]
    assert doc_ids, "expected wazuh_docs.json to be present in the image"
