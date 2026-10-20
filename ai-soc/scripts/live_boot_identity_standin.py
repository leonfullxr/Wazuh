#!/usr/bin/env python3
"""LOCAL-ONLY HTTPS stand-in for MCP JWKS and regional ALB public keys during live-boot-check."""

from __future__ import annotations

import os
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class _Handler(BaseHTTPRequestHandler):
    role = "jwks"
    kid = "standin-kid"
    jwks_body = b"{}"
    alb_pem = b""

    def log_message(self, format: str, *args: object) -> None:
        return

    def do_GET(self) -> None:
        if self.role == "jwks" and self.path == "/.well-known/jwks.json":
            body = self.jwks_body
        elif self.role == "alb" and self.path == f"/{self.kid}":
            body = self.alb_pem
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        content_type = "application/json" if self.role == "jwks" else "text/plain"
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        hits_path = os.environ.get("LOCAL_STANDIN_HITS_PATH", "").strip()
        if hits_path:
            path = Path(hits_path)
            try:
                current = int(path.read_text(encoding="utf-8").strip() or "0")
            except (OSError, ValueError):
                current = 0
            path.write_text(str(current + 1), encoding="utf-8")


def main() -> int:
    role = os.environ["LOCAL_STANDIN_ROLE"]
    port = int(os.environ.get("LOCAL_STANDIN_PORT", "443"))
    _Handler.role = role
    _Handler.kid = os.environ.get("LOCAL_STANDIN_KID", "alb-kid-1")
    if role == "jwks":
        _Handler.jwks_body = Path(os.environ["LOCAL_STANDIN_JWKS_PATH"]).read_bytes()
    else:
        _Handler.alb_pem = Path(os.environ["LOCAL_STANDIN_ALB_PEM_PATH"]).read_bytes()
    cert_path = Path(os.environ["LOCAL_STANDIN_TLS_CERT_PATH"])
    key_path = Path(os.environ["LOCAL_STANDIN_TLS_KEY_PATH"])
    server = ThreadingHTTPServer(("0.0.0.0", port), _Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    hostname = os.environ["LOCAL_STANDIN_HOSTNAME"]
    print(f"LOCAL_STANDIN_IDENTITY: {role} on https://{hostname}:{port}/", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
