#!/usr/bin/env python3
"""Golden set runner (D33). Exercises the FULL identity chain on purpose:
indexer Basic auth -> shim exchange -> turn JWT -> /v1/chat/sync.
A failure anywhere in that chain fails the run, which is exactly what a CI
gate should do.

Count assertions use LIVE references, not seed-time snapshots: the stack is a
real Wazuh, so the manager keeps producing organic alerts after seeding and
rolling windows age seeded alerts out - frozen counts drift within minutes.
The reference comes from the deterministic per-tool surface (/v1/tools/<name>),
so the expected number and the model's tool call share one code path. Each
reference is taken before the turn and, on mismatch, again after it, and any
value in between is accepted - that brackets alerts landing mid-turn.

Run from the host: python3 golden/run_evals.py
  WAI_EVAL_TIMEOUT_S   per-turn timeout in seconds (default 300; raise for
                       CPU-only local models)
  WAI_EVAL_RETRIES     re-ask a failing case this many times (default 0).
                       Keep 0 in CI; 1 smooths small-local-model stochasticity
                       in demo runs without hiding systematic failures.
Exit code 0 only when every case passes.

Writes golden/last_run.json with per-case results for model bake-offs.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import yaml

from live_gt import load_and_refresh
from connector_parse import parse_agent_message, split_connector_message
from auth import get_turn_jwt

SHIM = os.environ.get("WAI_EVAL_SHIM_URL", "http://localhost:8081")
SVC = os.environ.get("WAI_EVAL_SVC_URL", "http://localhost:8080")
INDEXER = os.environ.get("WAI_EVAL_INDEXER_URL", "https://localhost:9200")
INDEXER_USER = os.environ.get("INDEXER_ADMIN_USER", "admin")
INDEXER_PASSWORD = os.environ.get("INDEXER_ADMIN_PASSWORD", "SecretPassword")
EVAL_EDGE = os.environ.get("WAI_EVAL_EDGE", "direct")
USER = os.environ.get("WAI_EVAL_USER", os.environ.get("WAI_EVAL_KC_USER", "analyst1"))
PASSWORD = os.environ.get(
    "WAI_EVAL_PASSWORD", os.environ.get("WAI_EVAL_KC_PASSWORD", "analyst1")
)

TIMEOUT = float(os.environ.get("WAI_EVAL_TIMEOUT_S", "300"))
RETRIES = int(os.environ.get("WAI_EVAL_RETRIES", "0"))

HERE = Path(__file__).resolve().parent
AGENT_ID_FILE = HERE.parent / ".dashboard-assistant-agent-id"
ENV_SCOPED = "environment-scoped identity"


def _window(hours: int, floor: bool = False) -> dict:
    """Exact rolling window, or (floor=True) the same window with its start
    floored to UTC midnight - models legitimately read 'last 7 days' either
    way, so count references bracket both interpretations."""
    now = datetime.now(timezone.utc)
    gte = now - timedelta(hours=hours)
    if floor:
        gte = gte.replace(hour=0, minute=0, second=0, microsecond=0)
    return {"gte": gte.isoformat(), "lte": now.isoformat()}


# ground-truth key -> (tool, extra params, window hours) producing the same
# number the assistant's tool call must return. Keys absent here fall back to
# the frozen seed values (identifiers like top_rule_id do not drift).
REF_TOOLS: dict[str, tuple[str, dict, int]] = {
    "total_7d": ("count_alerts", {}, 24 * 7),
    "high_severity_7d": ("count_alerts", {"severity_gte": 10}, 24 * 7),
    "auth_failures_24h": ("auth_failures", {}, 24),
    "brute_force_total_24h": ("brute_force_summary", {}, 24),
}


def get_turn_jwt_for_eval() -> str:
    return get_turn_jwt(USER, PASSWORD, shim=SHIM)


def live_counts(headers: dict, key: str) -> tuple[int, int]:
    """(lo, hi) datastore truth across both window interpretations."""
    tool, extra, hours = REF_TOOLS[key]
    values = []
    for floor in (False, True):
        params = {"time_range": _window(hours, floor), **extra}
        r = httpx.post(
            f"{SVC}/v1/tools/{tool}", json=params, headers=headers, timeout=60
        )
        r.raise_for_status()
        values.append(int(r.json()["total_matching"]))
    return min(values), max(values)


def chat_sync(headers: dict, question: str) -> dict:
    """One turn. Retries 429s: after a timed-out case the server may still be
    finishing that turn, and the per-user admission slot stays busy until it
    does (D14) - waiting it out is correct, failing the next case is not."""
    last = None
    for _ in range(8):
        last = httpx.post(
            f"{SVC}/v1/chat/sync",
            json={"text": question},
            headers=headers,
            timeout=TIMEOUT,
        )
        if last.status_code == 429:
            time.sleep(20)
            continue
        if last.status_code == 503:
            detail = last.json().get("detail", last.text)
            raise httpx.HTTPStatusError(
                f"inference backend unreachable: {detail}",
                request=last.request,
                response=last,
            )
        last.raise_for_status()
        return last.json()
    raise httpx.HTTPStatusError(
        "still 429 after retries", request=last.request, response=last
    )


def _parse_agent_message(data: dict) -> str:
    return parse_agent_message(data)


def _split_connector_message(message: str) -> tuple[str, str]:
    return split_connector_message(message)


def agent_execute(question: str) -> dict:
    if not AGENT_ID_FILE.exists():
        sys.exit(f"{AGENT_ID_FILE.name} missing - run `make assistant-setup` first")
    agent_id = AGENT_ID_FILE.read_text().strip()
    last = None
    for _ in range(8):
        last = httpx.post(
            f"{INDEXER}/_plugins/_ml/agents/{agent_id}/_execute",
            json={"parameters": {"question": question}},
            auth=(INDEXER_USER, INDEXER_PASSWORD),
            verify=False,
            timeout=TIMEOUT,
        )
        if last.status_code in (429, 500):
            time.sleep(20 if last.status_code == 429 else 5)
            continue
        last.raise_for_status()
        raw = last.json()
        message = _parse_agent_message(raw)
        answer, label = _split_connector_message(message)
        return {
            "answer": answer,
            "verifiability": label,
            "tools_called": [],
            "checks": [],
            "corrections": [],
            "usage": {},
            "raw_agent": raw,
        }
    raise httpx.HTTPStatusError(
        "still 429 after retries", request=last.request, response=last
    )


def run_turn(question: str, headers: dict | None) -> dict:
    if EVAL_EDGE == "connector":
        return agent_execute(question)
    assert headers is not None
    return chat_sync(headers, question)


def substitute(text: str, gt: dict) -> str:
    return re.sub(r"\{\{gt\.(\w+)\}\}", lambda m: str(gt.get(m.group(1), "")), text)


def _count_variants(n: int) -> set[str]:
    return {str(n), f"{n:,}", f"{n:_}".replace("_", " "), f"{n:,}".replace(",", ".")}


_TYPOGRAPHY = {
    **dict.fromkeys(map(ord, "‐‑‒–—―−"), "-"),
    **dict.fromkeys(map(ord, "\u00a0\u2009\u202f"), " "),
}


def _normalize(s: str) -> str:
    return s.translate(_TYPOGRAPHY)


def check_case(
    case: dict,
    result: dict,
    gt: dict,
    counts: set[int] | None = None,
    *,
    connector_edge: bool = False,
) -> list[str]:
    failures: list[str] = []
    answer = _normalize(result.get("answer", ""))
    answer_cf = answer.casefold()
    tools = result.get("tools_called", [])
    checks = result.get("checks", [])
    verifiability = result.get("verifiability", "")

    if connector_edge:
        label_text = f"{verifiability} {answer}"
        if ENV_SCOPED not in label_text:
            failures.append(f"connector label missing {ENV_SCOPED!r}")
        if case.get("identity_only"):
            print(f"SKIPPED (env-scoped edge) {case['id']}: identity_only case")
            return failures

    if case.get("tools_any") and not connector_edge:
        if not set(case["tools_any"]) & set(tools):
            failures.append(f"expected one of {case['tools_any']}, tools called: {tools}")
    elif case.get("tools_any") and connector_edge:
        print(f"SKIPPED (env-scoped edge) {case['id']}: tools_any assertion")
    if case.get("tools_none") and not connector_edge and tools:
        failures.append(f"expected no tool calls, got {tools}")
    if case.get("checks_any") and not connector_edge:
        if not set(case["checks_any"]) & set(checks):
            failures.append(f"expected one of {case['checks_any']}, checks ran: {checks}")
    elif case.get("checks_any") and connector_edge:
        print(f"SKIPPED (env-scoped edge) {case['id']}: checks_any assertion")
    if key := case.get("answer_has_count"):
        if not connector_edge and "datastore_computed_counts" not in checks:
            failures.append("count asserted but datastore_computed_counts never ran")
        ns = counts if counts is not None else {int(gt[key])}
        variants: set[str] = set()
        for n in ns:
            variants |= _count_variants(n)
        if not any(v in answer for v in variants):
            expected = str(min(ns)) if len(ns) == 1 else f"{min(ns)}..{max(ns)}"
            failures.append(f"answer lacks expected count {expected} ({key})")
    if needles := case.get("answer_any"):
        if not any(
            substitute(needle, gt).casefold() in answer_cf for needle in needles
        ):
            failures.append(f"answer missing any of {needles!r}")
    for needle in case.get("answer_none", []):
        if needle.casefold() in answer_cf:
            failures.append(f"answer contains forbidden text: {needle!r}")

    if result.get("corrections") and not connector_edge:
        failures.append(f"unverified citations: {result['corrections']}")
    return failures


def run_suite(gt: dict, spec: dict) -> tuple[int, int, list[dict]]:
    passed, failed = 0, 0
    case_results: list[dict] = []
    connector_edge = EVAL_EDGE == "connector"
    if connector_edge:
        print(f"eval edge: connector (agent id from {AGENT_ID_FILE.name})")

    for case in spec["cases"]:
        question = substitute(case["question"], gt)
        key = case.get("answer_has_count")
        record = {"id": case["id"], "question": question, "passed": False, "failures": []}
        failures: list[str] = []
        result: dict = {}

        for _attempt in range(RETRIES + 1):
            try:
                ref_headers = {"Authorization": f"Bearer {get_turn_jwt_for_eval()}"}
                headers = None if connector_edge else ref_headers
                before = (
                    live_counts(ref_headers, key) if key in REF_TOOLS else None
                )
                t0 = time.monotonic()
                result = run_turn(question, headers)
                record["seconds"] = round(time.monotonic() - t0, 1)
                counts = set(range(before[0], before[1] + 1)) if before else None
                failures = check_case(
                    case, result, gt, counts, connector_edge=connector_edge
                )
                if (
                    failures
                    and before
                    and any("lacks expected count" in f for f in failures)
                ):
                    after = live_counts(ref_headers, key)
                    lo, hi = min(before[0], after[0]), max(before[1], after[1])
                    failures = check_case(
                        case,
                        result,
                        gt,
                        set(range(lo, hi + 1)),
                        connector_edge=connector_edge,
                    )
            except httpx.HTTPError as exc:
                failures = [f"transport/HTTP failure: {exc}"]
                result = {}
            if not failures:
                break

        record.update(
            {
                "tools_called": result.get("tools_called", []),
                "checks": result.get("checks", []),
                "verifiability": result.get("verifiability", ""),
                "corrections": result.get("corrections", []),
                "usage": result.get("usage", {}),
                "failures": failures,
                "passed": not failures,
            }
        )
        if result.get("answer"):
            record["answer_preview"] = result["answer"][:300]
        case_results.append(record)

        if failures:
            failed += 1
            print(f"FAIL  {case['id']}")
            for f in failures:
                print(f"      - {f}")
            if result.get("answer"):
                print(f"      answer: {result['answer'][:300]}")
        else:
            passed += 1
            label = result.get("verifiability", "")
            print(f"pass  {case['id']:<24} [{label}]")

    return passed, failed, case_results


def write_last_run(
    *,
    passed: int,
    failed: int,
    gt: dict,
    case_results: list[dict],
) -> Path:
    artifact = {
        "run_at": datetime.now(timezone.utc).isoformat(),
        "model_router": os.environ.get("WAI_MODEL_ROUTER", ""),
        "model_analysis": os.environ.get("WAI_MODEL_ANALYSIS", ""),
        "llm_provider": os.environ.get("WAI_LLM_PROVIDER", ""),
        "eval_edge": EVAL_EDGE,
        "passed": passed,
        "failed": failed,
        "total": passed + failed,
        "ground_truth": gt,
        "cases": case_results,
    }
    out = HERE / "last_run.json"
    out.write_text(json.dumps(artifact, indent=2))
    return out


def main() -> None:
    gt_path = HERE / "ground_truth.json"
    if not gt_path.exists():
        sys.exit("ground_truth.json missing - run `make seed` first")
    gt = load_and_refresh(str(gt_path))
    spec = yaml.safe_load((HERE / "golden.yaml").read_text())

    passed, failed, case_results = run_suite(gt, spec)
    out = write_last_run(passed=passed, failed=failed, gt=gt, case_results=case_results)

    total = passed + failed
    print(f"\n{passed}/{total} passed")
    print(f"artifact -> {out}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
