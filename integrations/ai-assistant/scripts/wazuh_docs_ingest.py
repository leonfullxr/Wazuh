#!/usr/bin/env python3
"""Build a version-pinned Wazuh docs corpus from documentation.wazuh.com/llms.txt (D60).

Fetches the curated AI index, follows listed Markdown pages for the pinned
Wazuh major.minor version, chunks heading-aware, and writes
tool-service/app/knowledge/wazuh_docs.json.

Never embeds tenant telemetry. Idempotent and re-runnable per WAZUH_VERSION.

Usage:
  python3 scripts/wazuh_docs_ingest.py
  WAZUH_VERSION=4.14.5 python3 scripts/wazuh_docs_ingest.py --max-pages 35
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
DEFAULT_OUT = ROOT / "tool-service" / "app" / "knowledge" / "wazuh_docs.json"
LLMS_URL = "https://documentation.wazuh.com/llms.txt"

# Import pure helpers from the tool-service package tree.
sys.path.insert(0, str(ROOT / "tool-service"))
from app.docs_kb_text import (  # noqa: E402
    canonical_html,
    chunk_markdown,
    parse_llms_entries,
    pin_url,
    select_pages,
    version_prefix,
)


def _fetch(url: str, timeout: float = 45.0) -> str:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "wazuh-ai-docs-ingest/1.0 (+https://github.com/wazuh)"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def ingest(
    *,
    wazuh_version: str,
    max_pages: int,
    out_path: Path,
    sleep_s: float = 0.15,
) -> dict:
    ver = version_prefix(wazuh_version)
    print(f"fetching {LLMS_URL} …", file=sys.stderr)
    llms = _fetch(LLMS_URL)
    entries = parse_llms_entries(llms)
    selected = select_pages(entries, max_pages=max_pages)
    print(
        f"llms.txt entries={len(entries)} selected={len(selected)} pin=/{ver}/",
        file=sys.stderr,
    )

    corpus: list[dict] = []
    errors: list[dict] = []
    for i, (title, md_url) in enumerate(selected, 1):
        pinned = pin_url(md_url, ver)
        html_url = canonical_html(pinned)
        try:
            md = _fetch(pinned)
            chunks = chunk_markdown(title, html_url, md)
            if not chunks and "/current/" not in md_url:
                md = _fetch(md_url)
                chunks = chunk_markdown(title, canonical_html(md_url), md)
            corpus.extend(chunks)
            print(f"[{i}/{len(selected)}] {title}: {len(chunks)} chunks", file=sys.stderr)
        except urllib.error.HTTPError as exc:
            errors.append({"url": pinned, "status": exc.code, "title": title})
            print(f"[{i}/{len(selected)}] FAIL {title}: HTTP {exc.code}", file=sys.stderr)
        except Exception as exc:  # noqa: BLE001
            errors.append({"url": pinned, "error": str(exc)[:200], "title": title})
            print(f"[{i}/{len(selected)}] FAIL {title}: {exc}", file=sys.stderr)
        time.sleep(sleep_s)

    by_id = {d["id"]: d for d in corpus}
    docs = list(by_id.values())
    meta = {
        "generated_by": "wazuh_docs_ingest.py",
        "llms_url": LLMS_URL,
        "wazuh_version": wazuh_version,
        "version_prefix": ver,
        "pages_selected": len(selected),
        "chunks": len(docs),
        "errors": errors,
    }
    payload = {"meta": meta, "documents": docs}
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {out_path} ({len(docs)} docs, {len(errors)} errors)", file=sys.stderr)
    return payload


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--version",
        default=os.environ.get("WAZUH_VERSION", "4.14.5"),
        help="Pinned Wazuh version (maps to /major.minor/ docs path)",
    )
    ap.add_argument("--max-pages", type=int, default=35)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--sleep", type=float, default=0.15)
    args = ap.parse_args()
    ingest(
        wazuh_version=args.version,
        max_pages=args.max_pages,
        out_path=args.out,
        sleep_s=args.sleep,
    )


if __name__ == "__main__":
    main()
