from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_IMAGE_HOME = "/" + "home" + "/" + "dynamodblocal"
_PRIVATE_SYNC = "Next" + "cloud"
_WORKFLOW_TERMS = (
    "first" + "mate",
    "cap" + "tain",
    "crew" + "mate",
    "in" + "box",
)
_DEVELOPMENT_TERMS = (
    "work" + "tree",
    "hand" + "off",
    "candidate" + " branch",
    "land" + "ed",
    "pending" + " landing",
    "wa" + "ve",
    "la" + "ne",
)
_BUNDLE_REFERENCE = re.compile(r"\bB[1-6]\b(?![-_])")
_ABSOLUTE_HOME = re.compile(r"(?:^|[^\w.-])/(?:home|Users)/[^/\s]+", re.IGNORECASE)
_INTERNAL_DOCS_PATH = "internal/" + "docs"


def _contains_absolute_home_path(content: str) -> bool:
    # The local DynamoDB image has a known container home; exempt only that
    # exact path token and descendants, with a boundary after its name.
    exact_image_home = re.compile(rf"(?<![\w.-]){re.escape(_IMAGE_HOME)}(?=/|(?=$|[\s\"'=,:;)]))")
    content = exact_image_home.sub("", content)
    return bool(_ABSOLUTE_HOME.search(content))


def _production_content_violations(content: str) -> list[str]:
    folded = content.casefold()
    violations: list[str] = []
    if _contains_absolute_home_path(content):
        violations.append("absolute home path")
    if _PRIVATE_SYNC.casefold() in folded:
        violations.append("private sync path")
    if any(term in folded for term in _WORKFLOW_TERMS):
        violations.append("internal workflow term")
    if any(term in folded for term in _DEVELOPMENT_TERMS):
        violations.append("development history term")
    if _BUNDLE_REFERENCE.search(content):
        violations.append("bundle reference")
    if _INTERNAL_DOCS_PATH in folded:
        violations.append("internal docs path")
    return violations


def test_tracked_production_files_contain_no_local_paths_or_workflow_terms() -> None:
    tracked_file = os.environ.get("AI_SOC_TRACKED_FILES_FILE")
    if tracked_file:
        tracked = Path(tracked_file).read_bytes().decode().split("\0")
    else:
        tracked = (
            subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True)
            .stdout.decode()
            .split("\0")
        )
    violations: list[str] = [
        f"{name}: tracked internal path" for name in tracked if name.startswith("internal/")
    ]
    for name in tracked:
        if not name or name.startswith("internal/"):
            continue
        path = ROOT / name
        if not path.is_file():
            continue
        content = path.read_bytes().decode("utf-8", errors="ignore")
        violations.extend(f"{name}: {reason}" for reason in _production_content_violations(content))

    assert not violations, "production tree contains private references: " + "; ".join(violations)


def test_container_home_exception_does_not_hide_similar_user_paths() -> None:
    planted_path = "/" + "home" + "/" + "dynamodblocal-alice/project"
    assert _contains_absolute_home_path(planted_path)


def test_production_scan_detects_internal_docs_path_and_history_terms() -> None:
    assert "internal docs path" in _production_content_violations(
        "See " + "internal/" + "docs/review.md for details."
    )
    assert "development history term" in _production_content_violations(
        "The old work" + "tree hand" + "off is complete."
    )
    assert "bundle reference" in _production_content_violations("B" + "6 owns this runner.")


def test_production_scan_allows_contract_ids_and_product_worker_terms() -> None:
    content = "B" + "6-G043.private uses a bounded worker and reviewer_id field."
    assert not _production_content_violations(content)
