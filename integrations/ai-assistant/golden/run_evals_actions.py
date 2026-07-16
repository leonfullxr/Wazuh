#!/usr/bin/env python3
"""Golden runner for V3.5 actions (direct execute or propose → confirm).

Bilingual action golden set (V3.5d). Exercises the full identity chain
(indexer Basic auth → shim → turn JWT) and dashboard executor against live Wazuh.

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

from auth import get_turn_jwt as _mint_turn_jwt

SHIM = os.environ.get("WAI_EVAL_SHIM_URL", "http://localhost:8081")
SVC = os.environ.get("WAI_EVAL_SVC_URL", "http://localhost:8080")
ENV_KEY = os.environ.get("WAI_EVAL_ENV_KEY") or os.environ.get("WAI_ENV_LAB_KEY", "")
USER = os.environ.get("WAI_EVAL_USER", "analyst1")
PASSWORD = os.environ.get("WAI_EVAL_PASSWORD", "analyst1")
TIMEOUT = float(os.environ.get("WAI_EVAL_ACTIONS_TIMEOUT_S", "120"))

HERE = Path(__file__).resolve().parent
OUT = HERE / "last_run_actions.json"


def get_turn_jwt(
    user: str | None = None, password: str | None = None
) -> str:
    return _mint_turn_jwt(user or USER, password or PASSWORD, shim=SHIM)


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


def _finalize_case(detail: dict) -> dict:
    detail["passed"] = bool(detail.get("ok")) and not detail.get("skipped")
    return detail


def run_case_direct(case: dict, headers: dict) -> dict:
    if case.get("reject_after_propose") or case.get("expect_operator") is False:
        return _finalize_case(
            {
                "id": case["id"],
                "lang": case.get("lang", "en"),
                "ok": True,
                "skipped": True,
                "reason": "propose/confirm flow not used in actions_direct mode",
            }
        )

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
        return _finalize_case(detail)

    result = resp.json()
    detail["result"] = result
    if "result_ok" in case and result.get("ok") is not case["result_ok"]:
        detail["ok"] = False
        detail["error"] = f"result.ok expected {case['result_ok']}, got {result.get('ok')}"
        return _finalize_case(detail)
    if "result_status" in case and result.get("status") != case["result_status"]:
        detail["ok"] = False
        detail["error"] = (
            f"result.status expected {case['result_status']!r}, got {result.get('status')!r}"
        )
        return _finalize_case(detail)
    return _finalize_case(_verify_dashboard(case, suffix, result, headers, detail))


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
        return _finalize_case(detail)

    body = propose.json()
    proposal_id = body.get("proposal_id")
    detail["proposal_id"] = proposal_id
    preview = body.get("preview", "")
    detail["preview"] = preview
    preview_cf = preview.casefold()

    if needles := case.get("preview_any"):
        if not any(str(n).casefold() in preview_cf for n in needles):
            detail["ok"] = False
            detail["error"] = f"preview missing any of {needles!r}"
            return _finalize_case(detail)
    if min_panels := case.get("preview_min_panels"):
        import re

        m = re.search(r"Panels\s*\((\d+)\)", preview)
        count = int(m.group(1)) if m else 0
        detail["preview_panel_count"] = count
        if count < int(min_panels):
            detail["ok"] = False
            detail["error"] = f"preview lists {count} panels, expected >= {min_panels}"
            return _finalize_case(detail)

    if case.get("skip_confirm"):
        return _finalize_case(detail)

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
        return _finalize_case(detail)

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
        return _finalize_case(detail)

    if expect_confirm == 403:
        return _finalize_case(detail)

    result = confirm.json().get("result", {})
    detail["result"] = result
    if "result_ok" in case and result.get("ok") is not case["result_ok"]:
        detail["ok"] = False
        detail["error"] = f"result.ok expected {case['result_ok']}, got {result.get('ok')}"
        return _finalize_case(detail)
    if "result_status" in case and result.get("status") != case["result_status"]:
        detail["ok"] = False
        detail["error"] = (
            f"result.status expected {case['result_status']!r}, got {result.get('status')!r}"
        )
        return _finalize_case(detail)

    return _finalize_case(_verify_dashboard(case, suffix, result, headers, detail))


def _chat_turn(
    text: str,
    conversation_id: str | None,
    *,
    edge: str,
    headers: dict,
    env_key: str,
) -> dict:
    if edge == "connector":
        r = httpx.post(
            f"{SVC}/v1/connector/analyze",
            json={"parameters": {"prompt": text}},
            headers={"X-Env-Key": env_key},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        body = r.json()
        return {
            "answer": body.get("output", {}).get("message", ""),
            "checks": body.get("checks") or [],
            "verifiability": body.get("verifiability", ""),
            "action_result": body.get("action_result"),
        }
    r = httpx.post(
        f"{SVC}/v1/chat/sync",
        json={"text": text, "conversation_id": conversation_id},
        headers=headers,
        timeout=TIMEOUT,
    )
    r.raise_for_status()
    return r.json()


def run_case_conversational(case: dict, headers: dict, health: dict) -> dict:
    if not health.get("actions_conversational"):
        return _finalize_case(
            {
                "id": case["id"],
                "lang": case.get("lang", "en"),
                "ok": True,
                "skipped": True,
                "reason": "actions_conversational disabled",
            }
        )
    if health.get("actions_direct"):
        return _finalize_case(
            {
                "id": case["id"],
                "lang": case.get("lang", "en"),
                "ok": True,
                "skipped": True,
                "reason": "conversational confirm requires propose/confirm mode",
            }
        )

    edge = case.get("edge", "direct")
    env_key = ENV_KEY.strip()
    if edge == "connector" and not env_key:
        return _finalize_case(
            {
                "id": case["id"],
                "lang": case.get("lang", "en"),
                "ok": False,
                "error": "WAI_EVAL_ENV_KEY required for connector conversational cases",
            }
        )

    skip_tier = case.get("skip_if_tier_enabled")
    if skip_tier and skip_tier in (health.get("action_tiers") or []):
        return _finalize_case(
            {
                "id": case["id"],
                "lang": case.get("lang", "en"),
                "ok": True,
                "skipped": True,
                "reason": f"tier {skip_tier!r} enabled on lab env",
            }
        )
    require_tier = case.get("require_tier")
    if require_tier and require_tier not in (health.get("action_tiers") or []):
        return _finalize_case(
            {
                "id": case["id"],
                "lang": case.get("lang", "en"),
                "ok": True,
                "skipped": True,
                "reason": f"tier {require_tier!r} not enabled on lab env",
            }
        )

    conv_id = f"golden-{case['id']}-{uuid.uuid4().hex[:8]}"
    propose_conv_id = None if edge == "connector" else conv_id
    params = dict(case.get("params") or {})
    suffix = uuid.uuid4().hex[:6]
    if "title" in params:
        params["title"] = f"{params['title']} [{suffix}]"

    propose_count = int(case.get("multi_propose", 1))
    propose_url = (
        f"{SVC}/v1/connector/propose"
        if edge == "connector"
        else f"{SVC}/v1/actions/propose"
    )
    propose_headers = (
        {"X-Env-Key": env_key} if edge == "connector" else headers
    )
    detail: dict = {
        "id": case["id"],
        "lang": case.get("lang", "en"),
        "edge": edge,
        "conversation_id": conv_id,
        "ok": True,
    }

    for _ in range(propose_count):
        propose = httpx.post(
            propose_url,
            json={
                "action": case["action"],
                "params": params,
                "conversation_id": propose_conv_id,
            },
            headers=propose_headers,
            timeout=TIMEOUT,
        )
        expect_propose = int(case.get("propose_status", 200))
        detail["propose_status"] = propose.status_code
        if propose.status_code != expect_propose:
            detail["ok"] = False
            detail["error"] = propose.text[:500]
            return _finalize_case(detail)
        if expect_propose != 200:
            return _finalize_case(detail)

    chat_text = case.get("chat_text", "yes")
    try:
        chat_body = _chat_turn(
            chat_text,
            conv_id if edge != "connector" else None,
            edge=edge,
            headers=headers,
            env_key=env_key,
        )
    except httpx.HTTPError as exc:
        detail["ok"] = False
        detail["error"] = str(exc)[:500]
        return _finalize_case(detail)

    detail["answer"] = chat_body.get("answer", "")[:500]
    detail["checks"] = chat_body.get("checks") or []
    detail["verifiability"] = chat_body.get("verifiability", "")

    expected_checks = case.get("checks") or []
    for chk in expected_checks:
        if chk not in detail["checks"]:
            detail["ok"] = False
            detail["error"] = (
                f"expected check {chk!r} in {detail['checks']!r}"
            )
            return _finalize_case(detail)

    action_result = chat_body.get("action_result") or {}
    if "result_ok" in case:
        got_ok = action_result.get("ok")
        if got_ok is not case["result_ok"]:
            detail["ok"] = False
            detail["error"] = f"action_result.ok expected {case['result_ok']}, got {got_ok}"
            return _finalize_case(detail)
    if "result_status" in case:
        got_status = action_result.get("status")
        if got_status != case["result_status"]:
            detail["ok"] = False
            detail["error"] = (
                f"action_result.status expected {case['result_status']!r}, "
                f"got {got_status!r}"
            )
            return _finalize_case(detail)

    if action_result.get("ok") and case.get("dashboard_title"):
        return _finalize_case(
            _verify_dashboard(
                case, suffix, action_result, headers, detail
            )
        )
    return _finalize_case(detail)


def main() -> None:
    health = wait_for_service()
    if not health.get("actions_enabled"):
        sys.exit(
            "actions disabled on tool-service — set WAI_ACTIONS_ENABLED=true and recreate"
        )

    direct = bool(health.get("actions_direct", False))
    mode = "direct" if direct else "propose/confirm"
    print(f"actions mode: {mode}")

    runner = run_case_direct if direct else run_case_propose
    jwt = get_turn_jwt()
    headers = auth_headers(jwt)
    cases = yaml.safe_load((HERE / "actions.yaml").read_text())["cases"]

    results = []
    for c in cases:
        if c.get("mode") == "conversational":
            results.append(run_case_conversational(c, headers, health))
            continue
        skip_tier = c.get("skip_if_tier_enabled")
        if skip_tier and skip_tier in (health.get("action_tiers") or []):
            results.append(
                _finalize_case(
                    {
                        "id": c["id"],
                        "lang": c.get("lang", "en"),
                        "ok": True,
                        "skipped": True,
                        "reason": f"tier {skip_tier!r} enabled on lab env",
                    }
                )
            )
            continue
        require_tier = c.get("require_tier")
        if require_tier and require_tier not in (health.get("action_tiers") or []):
            results.append(
                _finalize_case(
                    {
                        "id": c["id"],
                        "lang": c.get("lang", "en"),
                        "ok": True,
                        "skipped": True,
                        "reason": f"tier {require_tier!r} not enabled on lab env",
                    }
                )
            )
            continue
        results.append(runner(c, headers))
    passed = sum(1 for r in results if r.get("passed"))
    skipped = sum(1 for r in results if r.get("skipped"))
    report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "actions_mode": mode,
        "passed": passed,
        "total": len(results),
        "skipped": skipped,
        "cases": results,
    }
    OUT.write_text(json.dumps(report, indent=2) + "\n")

    for r in results:
        mark = "PASS" if r.get("passed") else ("SKIP" if r.get("skipped") else "FAIL")
        lang = r.get("lang", "en")
        reason = f" ({r.get('reason', r.get('skipped', ''))})" if r.get("skipped") else ""
        print(f"[{mark}] {r['id']} ({lang}){reason}")
        if not r.get("passed") and not r.get("skipped"):
            print(f"       {r.get('error', 'unknown error')}")

    print(f"\n{passed}/{len(results)} passed ({skipped} skipped) — wrote {OUT.name}")
    sys.exit(0 if passed == len(results) - skipped else 1)


if __name__ == "__main__":
    main()
