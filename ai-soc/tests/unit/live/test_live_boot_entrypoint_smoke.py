from __future__ import annotations

import ast
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import cast

import pytest
from pydantic import TypeAdapter

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from ai_soc.contracts.models import PageRequest
from scripts.live_boot_entrypoint_smoke import (
    BROWSER_ORIGIN,
    SmokeKeys,
    StandinTls,
    assert_indexer_standin_contacted,
    build_smoke_page_cursor,
    run_entrypoint_smoke,
)


def test_live_rest_smoke_rejects_422_for_valid_authenticated_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[tuple[str, dict[str, str], bytes]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("content-length", "0"))
            body = self.rfile.read(length)
            requests.append(
                (self.path, {key.lower(): value for key, value in self.headers.items()}, body)
            )
            if self.path == "/mcp":
                payload = {"result": {"tools": [{"name": "soc_ask"}]}}
                status = 200
            elif self.path == "/v1/fetches/page":
                payload = {"code": "INVALID_SCHEMA"}
                status = 422
            else:
                payload = {"code": "BAD_REQUEST"}
                status = 400
            encoded = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, _format: str, *_args: object) -> None:
            return None

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr("scripts.live_boot_entrypoint_smoke._mcp_token", lambda _pem: "mcp-token")
    monkeypatch.setattr("scripts.live_boot_entrypoint_smoke._alb_token", lambda _pem: "alb-token")
    monkeypatch.setattr(
        "scripts.live_boot_entrypoint_smoke._first_ui_asset", lambda: "/assets/app.js"
    )
    empty_tls = StandinTls(hostname="unused", cert_pem="", key_pem="")
    keys = SmokeKeys("", "", "", "", "", empty_tls, empty_tls, empty_tls, "")
    host, port = cast(tuple[str, int], server.server_address)
    try:
        with pytest.raises(RuntimeError, match="POST .* returned 422"):
            run_entrypoint_smoke(
                f"http://{host}:{port}", keys, page_cursor="valid-local-smoke-cursor"
            )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    rest_path, headers, body = requests[-1]
    assert rest_path == "/v1/fetches/page"
    request = TypeAdapter(PageRequest).validate_python(json.loads(body))
    assert request.environment_id == "alpha"
    assert request.cursor == "valid-local-smoke-cursor"
    assert headers["x-amzn-oidc-data"] == "alb-token"
    assert headers["origin"] == BROWSER_ORIGIN
    assert headers["x-soc-csrf"]
    assert headers["cookie"].startswith("__Host-soc-csrf=")


def test_live_boot_smoke_requires_an_indexer_standin_read(tmp_path: Path) -> None:
    hits = tmp_path / "indexer-hits.txt"
    hits.write_text("", encoding="utf-8")
    with pytest.raises(RuntimeError, match=r"exactly one search request \(observed 0\)"):
        assert_indexer_standin_contacted(hits)

    hits.write_text("search\n", encoding="utf-8")
    assert_indexer_standin_contacted(hits)
    hits.write_text("search\nsearch\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match=r"exactly one search request \(observed 2\)"):
        assert_indexer_standin_contacted(hits)


def test_live_boot_smoke_cursor_is_schema_valid_for_the_sealed_site() -> None:
    from tests.unit.live.live_boot_fixture import site_config

    cursor = build_smoke_page_cursor(site_config(), "b" * 40)
    request = PageRequest(environment_id="alpha", cursor=cursor)
    assert request.environment_id == "alpha"
    assert cursor.startswith("v1.current.")


def test_live_boot_acceptance_docker_runs_never_pull_images() -> None:
    scripts = Path(__file__).resolve().parents[3] / "scripts"
    commands: list[tuple[Path, list[str]]] = []
    for script in (scripts / "live_boot_check.py", scripts / "live_boot_entrypoint_smoke.py"):
        tree = ast.parse(script.read_text(encoding="utf-8"), filename=str(script))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr != "run" or not node.args:
                continue
            argv_node = node.args[0]
            if not isinstance(argv_node, ast.List) or len(argv_node.elts) < 2:
                continue
            prefix = [
                elt.value if isinstance(elt, ast.Constant) and isinstance(elt.value, str) else None
                for elt in argv_node.elts[:2]
            ]
            if prefix != ["docker", "run"]:
                continue
            argv = [
                elt.value
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
                else "<dynamic>"
                for elt in argv_node.elts
            ]
            commands.append((script, argv))

    assert commands, "expected direct docker run calls in live-boot acceptance scripts"
    missing_pull_guard = [
        f"{script.name}: {' '.join(argv[:8])}"
        for script, argv in commands
        if "--pull=never" not in argv
    ]
    assert not missing_pull_guard, "docker run must stay offline:\n" + "\n".join(missing_pull_guard)
