#!/usr/bin/env python3
"""Golden set runner (D33). Exercises the FULL identity chain on purpose:
Keycloak password grant -> shim exchange -> turn JWT -> /v1/chat/sync.
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

KC = "http://localhost:8085"
SHIM = "http://localhost:8081"
SVC = "http://localhost:8080"
REALM, CLIENT = "wazuh-poc", "wazuh-ai"
USER, PASSWORD = "analyst1", "analyst1"

TIMEOUT = float(os.environ.get("WAI_EVAL_TIMEOUT_S", "300"))
RETRIES = int(os.environ.get("WAI_EVAL_RETRIES", "0"))

HERE = Path(__file__).resolve().parent


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
}


def get_turn_jwt() -> str:
    oidc = httpx.post(
        f"{KC}/realms/{REALM}/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": CLIENT,
            "username": USER,
            "password": PASSWORD,
        },
        timeout=30,
    )
    oidc.raise_for_status()
    exchanged = httpx.post(
        f"{SHIM}/v1/token/exchange",
        headers={"Authorization": f"Bearer {oidc.json()['access_token']}"},
        timeout=30,
    )
    exchanged.raise_for_status()
    return exchanged.json()["access_token"]


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
        last.raise_for_status()
        return last.json()
    raise httpx.HTTPStatusError(
        "still 429 after retries", request=last.request, response=last
    )


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
    case: dict, result: dict, gt: dict, counts: set[int] | None = None
) -> list[str]:
    failures: list[str] = []
    answer = _normalize(result.get("answer", ""))
    answer_cf = answer.casefold()
    tools = result.get("tools_called", [])
    checks = result.get("checks", [])

    if case.get("tools_any") and not set(case["tools_any"]) & set(tools):
        failures.append(f"expected one of {case['tools_any']}, tools called: {tools}")
    if case.get("tools_none") and tools:
        failures.append(f"expected no tool calls, got {tools}")
    if case.get("checks_any") and not set(case["checks_any"]) & set(checks):
        failures.append(f"expected one of {case['checks_any']}, checks ran: {checks}")
    if key := case.get("answer_has_count"):
        if "datastore_computed_counts" not in checks:
            failures.append("count asserted but datastore_computed_counts never ran")
        ns = counts if counts is not None else {int(gt[key])}
        variants: set[str] = set()
        for n in ns:
            variants |= _count_variants(n)
        if not any(v in answer for v in variants):
            expected = str(min(ns)) if len(ns) == 1 else f"{min(ns)}..{max(ns)}"
            failures.append(f"answer lacks expected count {expected} ({key})")
    for needle in case.get("answer_any", []):
        needle = substitute(needle, gt)
        if needle.casefold() not in answer_cf:
            failures.append(f"answer missing expected text: {needle!r}")
            break
    for needle in case.get("answer_none", []):
        if needle.casefold() in answer_cf:
            failures.append(f"answer contains forbidden text: {needle!r}")

    if result.get("corrections"):
        failures.append(f"unverified citations: {result['corrections']}")
    return failures


def run_suite(gt: dict, spec: dict) -> tuple[int, int, list[dict]]:
    passed, failed = 0, 0
    case_results: list[dict] = []

    for case in spec["cases"]:
        question = substitute(case["question"], gt)
        key = case.get("answer_has_count")
        record = {"id": case["id"], "question": question, "passed": False, "failures": []}
        failures: list[str] = []
        result: dict = {}

        for _attempt in range(RETRIES + 1):
            try:
                headers = {"Authorization": f"Bearer {get_turn_jwt()}"}
                before = live_counts(headers, key) if key in REF_TOOLS else None
                result = chat_sync(headers, question)
                counts = set(range(before[0], before[1] + 1)) if before else None
                failures = check_case(case, result, gt, counts)
                if failures and before and any("lacks expected count" in f for f in failures):
                    after = live_counts(headers, key)
                    lo, hi = min(before[0], after[0]), max(before[1], after[1])
                    failures = check_case(case, result, gt, set(range(lo, hi + 1)))
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
