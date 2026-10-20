"""Stable public document pointer construction."""

from __future__ import annotations

from urllib.parse import quote

from ai_soc.content.catalog import safe_relative_path
from ai_soc.contracts.models import DocPointer, TopicDefinition


def document_pointer(
    topic: TopicDefinition, *, language: str, content_sha: str, docs_origin: str
) -> DocPointer | None:
    document = topic.public_document
    if document is None:
        return None
    if document.language != language:
        return None
    if len(content_sha) != 40 or any(char not in "0123456789abcdef" for char in content_sha):
        raise ValueError("content SHA must be a lowercase Git SHA-1")
    origin = docs_origin.rstrip("/")
    published_path = safe_relative_path(document.published_path).as_posix()
    path = "/".join(quote(part, safe="-._~") for part in published_path.split("/"))
    anchor = quote(document.anchor, safe="-._~")
    return DocPointer.model_validate(
        {
            "document_id": document.document_id,
            "source_path": document.source_path,
            "url": f"{origin}/commits/{content_sha}/{path}#{anchor}",
            "heading": document.heading,
            "content_sha": content_sha,
            "anchor": document.anchor,
            "document_sha256": document.sha256,
        }
    )
