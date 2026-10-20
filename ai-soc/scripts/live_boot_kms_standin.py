#!/usr/bin/env python3
"""LOCAL-ONLY KMS Sign protocol stand-in for live-boot-check."""

from __future__ import annotations

import base64
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils


class _Handler(BaseHTTPRequestHandler):
    private_key: object

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def do_POST(self) -> None:
        length = int(self.headers.get("content-length", "0"))
        try:
            request = json.loads(self.rfile.read(length))
            if (
                self.headers.get("x-amz-target") != "TrentService.Sign"
                or request.get("MessageType") != "DIGEST"
                or request.get("SigningAlgorithm") != "RSASSA_PKCS1_V1_5_SHA_256"
            ):
                self._write(400, {"message": "unsupported local KMS request"})
                return
            digest = base64.b64decode(request["Message"], validate=True)
            signature = self.private_key.sign(  # type: ignore[attr-defined]
                digest,
                padding.PKCS1v15(),
                utils.Prehashed(hashes.SHA256()),
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            self._write(400, {"message": "invalid local KMS request"})
            return
        self._write(
            200,
            {
                "KeyId": "arn:aws:kms:us-east-1:123456789012:key/alpha-key",
                "Signature": base64.b64encode(signature).decode("ascii"),
                "SigningAlgorithm": "RSASSA_PKCS1_V1_5_SHA_256",
            },
        )

    def _write(self, status: int, payload: dict[str, str]) -> None:
        encoded = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/x-amz-json-1.1")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def main() -> int:
    key_path = Path(os.environ["LOCAL_STANDIN_KMS_PRIVATE_KEY_PATH"])
    _Handler.private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    host = os.environ.get("LOCAL_STANDIN_HOST", "0.0.0.0")
    port = int(os.environ.get("LOCAL_STANDIN_PORT", "4566"))
    server = ThreadingHTTPServer((host, port), _Handler)
    print(f"LOCAL_STANDIN_KMS: Sign listener on {host}:{port}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
