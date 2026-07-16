#!/usr/bin/env python3
"""Golden runner for V3.5 actions (direct execute or propose → confirm).

Bilingual action golden set (V3.5d). Exercises the full identity chain
(Keycloak → shim → turn JWT) and dashboard executor against live Wazuh.

Run: python3 golden/run_evals_actions.py
  or: make evals-actions
"""
from __future__ import annotations

import json
import os
import sys
import time
import uuid
from pathlib import Path

import httpx
import yaml

KC = os.environ.get("WAI_EVAL_KC_URL", "http://localhost:8085")
SHIM = os.environ.get("WAI_EVAL_SHIM_URL", "http://localhost:8081")
SVC = os.environ.get("WAI_EVAL_SVC_URL", "http://localhost:8080")
REALM = os.environ.get("WAI_EVAL_KC_REALM", "wazuh-poc")
CLIENT = os.environ.get("WAI_EVAL_KC_CLIENT", "wazuh-ai")
USER = os.environ.get("WAI_EVAL_KC_USER", "analyst1")
PASSWORD = os.environ.get("WAI_EVAL_KC_PASSWORD", "analyst1")
TIMEOUT = float(os.environ.get("WAI_EVAL_ACTIONS_TIMEOUT_S", "120"))

HERE = Path(__file__).resolve().parent
OUT = HERE / "last_run_actions.json"


def get_turn_jwt(
    user: str | None = None, password: str | None = None
) -> str:
    user = user or USER
    password = password or PASSWORD
    oidc = httpx.post(
        f"{KC}/realms/{REALM}/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": CLIENT,
            "username": user,
            "password": password,
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


def auth_headers(jwt: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {jwt}"}


def wait_for_service() -> dict:
    for _ in range(30):
        try:
            r = httpx.get(f"{SVC}/healthz", timeout=5)
            if r.status_code == 200:
                return r.json()
        except httpx.HTTPError:
            pass
        time.sleep(2)
    sys.exit(f"tool-service not healthy at {SVC}/healthz")


def list_dashboard_titles(headers: dict) -> list[str]:
    r = httpx.post(
        f"{SVC}/v1/tools/list_dashboards",
        json={"size": 100},
        headers=headers,
        timeout=60,
    )
    r.raise_for_status()
    return [
        obj.get("title", "")
        for obj in r.json().get("objects", [])
        if obj.get("type") == "dashboard"
    ]


def _verify_dashboard(
    case: dict,
    suffix: str,
    result: dict,
    headers: dict,
    detail: dict,
) -> dict:
    title_needle = case.get("dashboard_title")
    if not title_needle or not result.get("ok"):
        return detail
    expected_title = f"{title_needle} [{suffix}]"
    details = result.get("details") or {}
    found = details.get("title") == expected_title
    verify_via = "action_result"
    if not found:
        for _ in range(8):
            titles = list_dashboard_titles(headers)
            if expected_title in titles:
                found = True
                verify_via = "list_dashboards"
                break
            time.sleep(2)
    detail["dashboard_title_expected"] = expected_title
    detail["dashboard_found"] = found
    detail["dashboard_verify_via"] = verify_via if found else None
    if not found:
        detail["ok"] = False
        detail["error"] = (
            f"dashboard not verified (result title={details.get('title')!r}, "
            f"expected {expected_title!r})"
        )
    return detail


def run_case_direct(case: dict, headers: dict) -> dict:
    if case.get("reject_after_propose") or case.get("expect_operator") is False:
        return {
            "id": case["id"],
            "lang": case.get("lang", "en"),
            "ok": True,
            "skipped": "propose/confirm flow not used in actions_direct mode",
        }

    params = dict(case.get("params") or {})
    suffix = uuid.uuid4().hex[:6]
    if "title" in params:
        params["title"] = f"{params['title']} [{suffix}]"

    resp = httpx.post(
        f"{SVC}/v1/actions/propose",
        json={"action": case["action"], "params": params},
        headers=headers,
        timeout=TIMEOUT,
    )
    expect = int(case.get("propose_status", 200))
    detail: dict = {
        "id": case["id"],
        "lang": case.get("lang", "en"),
        "ok": resp.status_code == expect,
        "execute_status": resp.status_code,
        "expect_execute": expect,
    }
    if not detail["ok"]:
        detail["error"] = resp.text[:500]
        return detail

    result = resp.json()
    detail["result"] = result
    if "result_ok" in case and result.get("ok") is not case["result_ok"]:
        detail["ok"] = False
        detail["error"] = f"result.ok expected {case['result_ok']}, got {result.get('ok')}"
        return detail
    if "result_status" in case and result.get("status") != case["result_status"]:
        detail["ok"] = False
        detail["error"] = (
            f"result.status expected {case['result_status']!r}, got {result.get('status')!r}"
        )
        return detail
    return _verify_dashboard(case, suffix, result, headers, detail)


def run_case_propose(case: dict, headers: dict) -> dict:
    params = dict(case.get("params") or {})
    suffix = uuid.uuid4().hex[:6]
    if "title" in params:
        params["title"] = f"{params['title']} [{suffix}]"

    propose = httpx.post(
        f"{SVC}/v1/actions/propose",
        json={"action": case["action"], "params": params},
        headers=headers,
        timeout=TIMEOUT,
    )
    expect_propose = int(case.get("propose_status", 200))
    detail: dict = {
        "id": case["id"],
        "lang": case.get("lang", "en"),
        "ok": propose.status_code == expect_propose,
        "propose_status": propose.status_code,
        "expect_propose": expect_propose,
    }
    if not detail["ok"]:
        detail["error"] = propose.text[:500]
        return detail

    body = propose.json()
    proposal_id = body.get("proposal_id")
    detail["proposal_id"] = proposal_id
    detail["preview"] = body.get("preview", "")

    confirm_user = case.get("confirm_user", USER)
    confirm_password = case.get("confirm_password", PASSWORD)
    confirm_headers = headers
    if confirm_user != USER or confirm_password != PASSWORD:
        confirm_headers = auth_headers(
            get_turn_jwt(confirm_user, confirm_password)
        )

    if case.get("reject_after_propose"):
        reject = httpx.post(
            f"{SVC}/v1/actions/{proposal_id}/reject",
            headers=confirm_headers,
            timeout=TIMEOUT,
        )
        detail["reject_status"] = reject.status_code
        if reject.status_code != 200:
            detail["ok"] = False
            detail["error"] = reject.text[:500]
            return detail
        status = reject.json().get("status")
        detail["proposal_status"] = status
        if status != "rejected":
            detail["ok"] = False
            detail["error"] = f"expected rejected, got {status!r}"
        return detail

    confirm = httpx.post(
        f"{SVC}/v1/actions/{proposal_id}/confirm",
        json={"idempotency_key": f"golden-{case['id']}-{suffix}"},
        headers=confirm_headers,
        timeout=TIMEOUT,
    )
    expect_confirm = int(case.get("confirm_status", 200))
    detail["confirm_status"] = confirm.status_code
    detail["expect_confirm"] = expect_confirm
    if confirm.status_code != expect_confirm:
        detail["ok"] = False
        detail["error"] = confirm.text[:500]
        return detail

    if expect_confirm == 403:
        return detail

    result = confirm.json().get("result", {})
    detail["result"] = result
    if "result_ok" in case and result.get("ok") is not case["result_ok"]:
        detail["ok"] = False
        detail["error"] = f"result.ok expected {case['result_ok']}, got {result.get('ok')}"
        return detail
    if "result_status" in case and result.get("status") != case["result_status"]:
        detail["ok"] = False
        detail["error"] = (
            f"result.status expected {case['result_status']!r}, got {result.get('status')!r}"
        )
        return detail

    return _verify_dashboard(case, suffix, result, headers, detail)


def main() -> None:
    health = wait_for_service()
    if not health.get("actions_enabled"):
        sys.exit(
            "actions disabled on tool-service — set WAI_ACTIONS_ENABLED=true and recreate"
        )

    direct = bool(health.get("actions_direct", True))
    mode = "direct" if direct else "propose/confirm"
    print(f"actions mode: {mode}")

    jwt = get_turn_jwt()
    headers = auth_headers(jwt)
    cases = yaml.safe_load((HERE / "actions.yaml").read_text())["cases"]

    runner = run_case_direct if direct else run_case_propose
    results = [runner(c, headers) for c in cases]
    passed = sum(1 for r in results if r.get("ok"))
    report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "actions_mode": mode,
        "passed": passed,
        "total": len(results),
        "cases": results,
    }
    OUT.write_text(json.dumps(report, indent=2) + "\n")

    for r in results:
        mark = "PASS" if r.get("ok") else "FAIL"
        lang = r.get("lang", "en")
        skip = f" (skipped: {r['skipped']})" if r.get("skipped") else ""
        print(f"[{mark}] {r['id']} ({lang}){skip}")
        if not r.get("ok"):
            print(f"       {r.get('error', 'unknown error')}")

    print(f"\n{passed}/{len(results)} passed — wrote {OUT.name}")
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
