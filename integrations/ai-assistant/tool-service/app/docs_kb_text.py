"""Pure helpers for Wazuh docs KB ingest (D60) - no network, no CFG."""
from __future__ import annotations

import hashlib
import re

_MD_LINK = re.compile(
    r"\*\*\[([^\]]+)\]\((https://documentation\.wazuh\.com/[^)]+\.md)\)\*\*"
)
_HEADING = re.compile(r"^(#{1,3})\s+(.+?)\s*$", re.M)
_HTML_COMMENT = re.compile(r"<!--.*?-->", re.S)
_IMAGE = re.compile(r"!\[([^\]]*)\]\([^)]+\)")
_LINK = re.compile(r"\[([^\]]+)\]\([^)]+\)")

PRIORITY_SUBSTR = (
    "/user-manual/capabilities/",
    "/user-manual/ruleset/",
    "/user-manual/api/",
    "/user-manual/agent/",
    "/user-manual/manager/",
    "/proof-of-concept-guide/",
    "/compliance/",
    "/getting-started/",
    "/installation-guide/",
    "/quickstart",
    "/user-manual/reference/",
)


def version_prefix(wazuh_version: str) -> str:
    parts = wazuh_version.strip().split(".")
    if len(parts) >= 2:
        return f"{parts[0]}.{parts[1]}"
    return wazuh_version.strip() or "current"


def pin_url(url: str, ver_prefix: str) -> str:
    if "/current/" in url:
        return url.replace("/current/", f"/{ver_prefix}/", 1)
    return url


def canonical_html(md_url: str) -> str:
    if md_url.endswith(".md"):
        return md_url[:-3] + ".html"
    return md_url


def slug(title: str, section: str) -> str:
    base = f"{title}-{section}".lower()
    base = re.sub(r"[^a-z0-9]+", "-", base).strip("-")
    base = base[:72] or "doc"
    digest = hashlib.sha1(f"{title}|{section}".encode()).hexdigest()[:6]
    return f"doc-{base}-{digest}"


def parse_llms_entries(llms_text: str) -> list[tuple[str, str]]:
    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    for m in _MD_LINK.finditer(llms_text):
        title, url = m.group(1).strip(), m.group(2).strip()
        if url in seen:
            continue
        seen.add(url)
        out.append((title, url))
    return out


def select_pages(
    entries: list[tuple[str, str]], *, max_pages: int
) -> list[tuple[str, str]]:
    pri: list[tuple[str, str]] = []
    rest: list[tuple[str, str]] = []
    for title, url in entries:
        if "documentation.wazuh.com" not in url:
            continue
        if any(s in url for s in PRIORITY_SUBSTR):
            pri.append((title, url))
        else:
            rest.append((title, url))
    return (pri + rest)[:max_pages]


def clean_markdown(text: str) -> str:
    text = _HTML_COMMENT.sub("", text)
    text = _IMAGE.sub(r"\1", text)
    text = _LINK.sub(r"\1", text)
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def split_bounded(text: str, max_chars: int) -> list[str]:
    if len(text) <= max_chars:
        return [text]
    chunks: list[str] = []
    paras = re.split(r"\n\n+", text)
    buf = ""
    for p in paras:
        p = p.strip()
        if not p:
            continue
        if len(p) > max_chars:
            if buf:
                chunks.append(buf.strip())
                buf = ""
            for i in range(0, len(p), max_chars):
                chunks.append(p[i : i + max_chars].strip())
            continue
        if buf and len(buf) + 2 + len(p) > max_chars:
            chunks.append(buf.strip())
            buf = p
        else:
            buf = f"{buf}\n\n{p}".strip() if buf else p
    if buf:
        chunks.append(buf.strip())
    return [c for c in chunks if c]


def chunk_markdown(
    title: str,
    url_html: str,
    md_text: str,
    *,
    max_chars: int = 1200,
) -> list[dict]:
    cleaned = clean_markdown(md_text)
    if not cleaned:
        return []

    parts: list[tuple[str, str]] = []
    matches = list(_HEADING.finditer(cleaned))
    if not matches:
        parts.append((title, cleaned))
    else:
        if matches[0].start() > 0:
            pre = cleaned[: matches[0].start()].strip()
            if pre:
                parts.append((title, pre))
        for i, m in enumerate(matches):
            section = m.group(2).strip()
            start = m.end()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(cleaned)
            body = cleaned[start:end].strip()
            if body:
                parts.append((section, body))

    docs: list[dict] = []
    for section, body in parts:
        pieces = split_bounded(body, max_chars)
        for idx, piece in enumerate(pieces):
            sec_label = section if len(pieces) == 1 else f"{section} ({idx + 1})"
            docs.append(
                {
                    "id": slug(title, sec_label),
                    "title": title,
                    "url": url_html,
                    "section": sec_label,
                    "source": "wazuh-docs",
                    "text": piece,
                    "tags": ["wazuh-docs", "documentation"],
                }
            )
    return docs
