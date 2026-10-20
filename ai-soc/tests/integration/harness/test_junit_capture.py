from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from scripts.junit_capture import extract_junit_document  # noqa: E402


def test_runner_stdout_extraction_keeps_actual_test_properties_and_results() -> None:
    captured = "launcher setup\n<testsuites><testsuite><testcase classname='x' name='a'>"
    captured += "<properties><property name='case_id' value='case-a'/></properties>"
    captured += "</testcase></testsuite></testsuites>cleanup complete\n"

    xml_bytes = extract_junit_document(captured)
    root = ET.fromstring(xml_bytes)
    testcase = root.find(".//testcase")
    prop = root.find(".//property")

    assert root.tag == "testsuites"
    assert testcase is not None
    assert testcase.attrib == {"classname": "x", "name": "a"}
    assert prop is not None
    assert prop.attrib == {"name": "case_id", "value": "case-a"}


@pytest.mark.parametrize(
    "captured, message",
    [
        ("runner failed before collection", "no JUnit XML root"),
        ("<testsuites></testsuites>", "no collected test cases"),
        ("<testsuites><testsuite>", "no closing </testsuites> tag"),
        ("<testsuites><testsuite></testsuites>", "malformed JUnit XML"),
    ],
)
def test_runner_stdout_extraction_rejects_missing_empty_or_malformed_junit(
    captured: str, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        extract_junit_document(captured)
