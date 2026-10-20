#!/usr/bin/env python3
"""LOCAL-ONLY HTTPS Wazuh Indexer stand-in for the live container smoke."""

from __future__ import annotations

import json
import os
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def do_POST(self) -> None:
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length)
        if self.path != "/_search":
            self._write(404, {"error": "not found"})
            return
        try:
            request = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._write(400, {"error": "invalid JSON"})
            return
        if not isinstance(request, dict) or not isinstance(request.get("pit"), dict):
            self._write(400, {"error": "expected PIT search"})
            return
        hits_path = Path(os.environ["LOCAL_STANDIN_HITS_PATH"])
        with hits_path.open("a", encoding="utf-8") as handle:
            handle.write("search\n")
        self._write(
            200,
            {
                "took": 1,
                "timed_out": False,
                "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
                "hits": {
                    "total": {"value": 1, "relation": "eq"},
                    "hits": [
                        {
                            "_index": "wazuh-alerts-alpha-2026.10.07",
                            "_id": "local-live-boot-row-001",
                            "_source": {
                                "@timestamp": "2026-10-07T07:00:00Z",
                                "agent": {"id": "007", "name": "alpha-agent"},
                                "rule": {"id": "5710", "level": 5, "groups": ["auth"]},
                                "data": {"srcip": "192.0.2.10", "dstip": "192.0.2.8"},
                            },
                            "sort": [
                                "2026-10-07T07:00:00Z",
                                "wazuh-alerts-alpha-2026.10.07",
                                "local-live-boot-row-001",
                            ],
                        }
                    ],
                },
            },
        )

    def _write(self, status: int, payload: dict[str, object]) -> None:
        encoded = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Content-Encoding", "identity")
        self.end_headers()
        self.wfile.write(encoded)


def main() -> int:
    cert_path = Path(os.environ["LOCAL_STANDIN_TLS_CERT_PATH"])
    key_path = Path(os.environ["LOCAL_STANDIN_TLS_KEY_PATH"])
    host = os.environ.get("LOCAL_STANDIN_HOST", "0.0.0.0")
    port = int(os.environ.get("LOCAL_STANDIN_PORT", "9200"))
    server = ThreadingHTTPServer((host, port), _Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f"LOCAL_STANDIN_INDEXER: HTTPS listener on {host}:{port}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
