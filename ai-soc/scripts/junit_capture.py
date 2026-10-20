#!/usr/bin/env python3
"""Extract a pytest JUnit document streamed through a task-owned runner."""

from __future__ import annotations

import argparse
import re
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT_TAGS = ("testsuites", "testsuite")


def extract_junit_document(captured_output: str) -> bytes:
    """Return the single nonempty JUnit XML document embedded in runner output."""
    matches: list[tuple[int, str]] = []
    for tag in ROOT_TAGS:
        match = re.search(rf"<{tag}(?=\s|>)", captured_output)
        if match is not None:
            matches.append((match.start(), tag))
    if not matches:
        raise ValueError("runner output contains no JUnit XML root")

    start, root_tag = min(matches)
    closing = f"</{root_tag}>"
    end = captured_output.rfind(closing)
    if end < start:
        raise ValueError(f"runner output has no closing {closing} tag")
    end += len(closing)

    try:
        root = ET.fromstring(captured_output[start:end])
    except ET.ParseError as error:
        raise ValueError("runner output contains malformed JUnit XML") from error
    if root.tag != root_tag:
        raise ValueError("runner output JUnit root changed during parsing")
    if not root.findall(".//testcase"):
        raise ValueError("runner JUnit document contains no collected test cases")
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    document = extract_junit_document(args.input.read_text(encoding="utf-8"))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(document)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
