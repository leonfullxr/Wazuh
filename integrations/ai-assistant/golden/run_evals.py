#!/usr/bin/env python3
"""Golden set runner (D33). Exercises the FULL identity chain on purpose:
Keycloak password grant -> shim exchange -> turn JWT -> /v1/chat/sync.
A failure anywhere in that chain fails the run, which is exactly what a CI
gate should do.

Run from the host: python3 golden/run_evals.py
Exit code 0 only when every case passes.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import httpx
import yaml

KC = "http://localhost:8085"
SHIM = "http://localhost:8081"
SVC = "http://localhost:8080"
REALM, CLIENT = "wazuh-poc", "wazuh-ai"
USER, PASSWORD = "analyst1", "analyst1"

HERE = Path(__file__).resolve().parent


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


def substitute(text: str, gt: dict) -> str:
    return re.sub(r"\{\{gt\.(\w+)\}\}", lambda m: str(gt.get(m.group(1), "")), text)


def check_case(case: dict, result: dict, gt: dict) -> list[str]:
    failures: list[str] = []
    answer = result.get("answer", "")
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
        n = gt[key]
        variants = {str(n), f"{n:,}", f"{n:_}".replace("_", " "), f"{n:,}".replace(",", ".")}
        if not any(v in answer for v in variants):
            failures.append(f"answer lacks ground-truth count {n} ({key})")
    for needle in case.get("answer_any", []):
        needle = substitute(needle, gt)
        if needle.casefold() not in answer_cf:
            failures.append(f"answer missing expected text: {needle!r}")
            break
    for needle in case.get("answer_none", []):
        if needle.casefold() in answer_cf:
            failures.append(f"answer contains forbidden text: {needle!r}")

    # Global honesty gate: no unverified citations anywhere.
    if result.get("corrections"):
        failures.append(f"unverified citations: {result['corrections']}")
    return failures


def main() -> None:
    gt_path = HERE / "ground_truth.json"
    if not gt_path.exists():
        sys.exit("ground_truth.json missing - run `make seed` first")
    gt = json.loads(gt_path.read_text())
    spec = yaml.safe_load((HERE / "golden.yaml").read_text())

    jwt_token = get_turn_jwt()
    headers = {"Authorization": f"Bearer {jwt_token}"}

    passed, failed = 0, 0
    for case in spec["cases"]:
        question = substitute(case["question"], gt)
        try:
            r = httpx.post(
                f"{SVC}/v1/chat/sync",
                json={"text": question},
                headers=headers,
                timeout=180,
            )
            r.raise_for_status()
            result = r.json()
            failures = check_case(case, result, gt)
        except httpx.HTTPError as exc:
            failures = [f"transport/HTTP failure: {exc}"]
            result = {}

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

    total = passed + failed
    print(f"\n{passed}/{total} passed")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
