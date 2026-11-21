#!/usr/bin/env python3
"""Tiny HTTPS OpenID Connect provider for exercising wazuh-mcp.

Discovery requires https URLs, and the MCP server verifies the IdP certificate.
This writes a one-day self-signed certificate and prints the path. Start
wazuh-mcp with SSL_CERT_FILE set to that certificate.

    python3 dev/mock_idp.py
    export SSL_CERT_FILE=<printed cert>
    export OAUTH_IDP_ISSUER=https://127.0.0.1:8443
    export OAUTH_IDP_CLIENT_ID=wazuh-mcp
    export OAUTH_IDP_CLIENT_SECRET=mock-secret
    export OAUTH_IDP_GROUP_SCOPE_MAP='{"responders":"wazuh:read wazuh:write"}'
    export OAUTH_IDP_DEFAULT_SCOPE=wazuh:read

Allow signs in as analyst@example.com in the responders group. Deny redirects
back with error=access_denied. The IdP does not replace a real provider.
"""

from __future__ import annotations

import base64
import hashlib
import json
import ssl
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

ISSUER = "https://127.0.0.1:8443"
KID = "mock-idp-1"
_PRIVATE = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_JWK = json.loads(RSAAlgorithm.to_jwk(_PRIVATE.public_key()))
_JWK["kid"] = KID
_JWK["use"] = "sig"
_JWK["alg"] = "RS256"
_PENDING: dict[str, dict] = {}
_CODES: dict[str, dict] = {}
_LOCK = threading.Lock()

_CSS = """
:root { color-scheme: light dark; --bg:#eef2ef; --card:#fff; --ink:#17241e; --line:#d5e0d8; --accent:#1f6b45; --accent-ink:#fff; --muted:#5c6d63; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#101814; --card:#1a2820; --ink:#e7f0ea; --line:#31483c; --accent:#3d9a68; --accent-ink:#06210f; --muted:#b7c7bd; }
}
* { box-sizing: border-box; }
body { margin:0; min-height:100vh; display:flex; align-items: safe center; justify-content:center; padding:32px 16px;
  font:16px/1.45 system-ui,sans-serif; background:var(--bg); color:var(--ink); }
main { width:min(100%, 28rem); background:var(--card); border:1px solid var(--line); border-radius:16px; padding:28px 24px; }
h1 { font-size:1.4rem; margin:0 0 8px; }
p { margin:0 0 12px; }
.eyebrow { margin:0 0 8px; font-size:.75rem; letter-spacing:.12em; text-transform:uppercase; color:var(--accent); font-weight:700; }
label { display:block; font-weight:650; margin:8px 0 6px; }
input { width:100%; min-height:44px; padding:10px 12px; font:inherit; color:inherit; background:transparent; border:1px solid var(--line); border-radius:10px; }
.actions { display:flex; gap:10px; margin-top:16px; }
button { min-height:44px; padding:10px 16px; font:inherit; font-weight:650; border-radius:10px; cursor:pointer; }
.primary { background:var(--accent); color:var(--accent-ink); border:0; flex:1; }
.secondary { background:transparent; color:inherit; border:1px solid var(--line); }
.err { color:#9d1230; font-weight:650; }
@media (prefers-color-scheme: dark) { .err { color:#ffb3c0; } }
@media (max-width: 480px) { .actions { flex-direction:column-reverse; } main { padding:22px 16px; } }
"""


def _page(title: str, body: str, status: int = 200) -> tuple[int, bytes]:
    html = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{title}</title>
<style>{_CSS}</style></head><body><main><p class="eyebrow">Mock identity provider</p>{body}</main></body></html>"""
    return status, html.encode()


def _s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _id_token(audience: str, nonce: str, email: str, groups: list[str]) -> str:
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "sub": email,
        "aud": audience,
        "iat": now,
        "exp": now + 300,
        "nonce": nonce,
        "email": email,
        "email_verified": True,
        "groups": groups,
    }
    return jwt.encode(claims, _PRIVATE, algorithm="RS256", headers={"kid": KID})


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:
        print(f"[idp] {fmt % args}")

    def _send(self, status: int, body: bytes, content_type: str, extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location: str) -> None:
        self._send(303, b"", "text/plain", {"Location": location})

    def _query(self) -> dict:
        return parse_qs(urlsplit(self.path).query)

    def _form(self) -> dict:
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length) if length else b""
        return parse_qs(raw.decode())

    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path == "/.well-known/openid-configuration":
            body = json.dumps({
                "issuer": ISSUER,
                "authorization_endpoint": f"{ISSUER}/authorize",
                "token_endpoint": f"{ISSUER}/token",
                "jwks_uri": f"{ISSUER}/jwks",
                "response_types_supported": ["code"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
                "code_challenge_methods_supported": ["S256"],
            }).encode()
            self._send(200, body, "application/json")
            return
        if path == "/jwks":
            self._send(200, json.dumps({"keys": [_JWK]}).encode(), "application/json")
            return
        if path == "/authorize":
            query = self._query()
            needed = ("client_id", "redirect_uri", "state", "nonce", "code_challenge")
            if any(not query.get(name) for name in needed):
                _, body = _page("Sign-in request rejected", "<h1>This sign-in request was rejected</h1><p>A required parameter is missing.</p>", 400)
                self._send(400, body, "text/html; charset=utf-8")
                return
            hidden = "".join(
                f'<input type="hidden" name="{name}" value="{query[name][0]}">'
                for name in ("client_id", "redirect_uri", "state", "nonce", "code_challenge", "scope")
                if query.get(name)
            )
            _, body = _page(
                "Sign in",
                "<h1>Sign in to Wazuh</h1>"
                "<p>This mock provider will return an ID token for the address below, in the responders group.</p>"
                f'<form method="post" action="/authorize">{hidden}'
                '<label for="email">Email</label><input id="email" name="email" type="email" value="analyst@example.com" required>'
                '<div class="actions"><button class="secondary" name="decision" value="deny">Deny</button>'
                '<button class="primary" name="decision" value="allow">Continue</button></div></form>',
            )
            self._send(200, body, "text/html; charset=utf-8")
            return
        _, body = _page("Not found", "<h1>This page does not exist</h1>", 404)
        self._send(404, body, "text/html; charset=utf-8")

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        form = self._form()
        if path == "/authorize":
            redirect = (form.get("redirect_uri") or [""])[0]
            state = (form.get("state") or [""])[0]
            if not redirect:
                _, body = _page("Sign-in request rejected", "<h1>Missing redirect</h1>", 400)
                self._send(400, body, "text/html; charset=utf-8")
                return
            if (form.get("decision") or ["allow"])[0] == "deny":
                self._redirect(redirect + ("&" if "?" in redirect else "?") + urlencode({"error": "access_denied", "state": state}))
                return
            code = base64.urlsafe_b64encode(hashlib.sha256(f"{state}{time.time()}".encode()).digest()).decode().rstrip("=")
            with _LOCK:
                _CODES[code] = {
                    "client_id": (form.get("client_id") or [""])[0],
                    "redirect_uri": redirect,
                    "nonce": (form.get("nonce") or [""])[0],
                    "challenge": (form.get("code_challenge") or [""])[0],
                    "email": (form.get("email") or ["analyst@example.com"])[0],
                }
            self._redirect(redirect + ("&" if "?" in redirect else "?") + urlencode({"code": code, "state": state}))
            return
        if path == "/token":
            code = (form.get("code") or [""])[0]
            verifier = (form.get("code_verifier") or [""])[0]
            with _LOCK:
                pending = _CODES.pop(code, None)
            if pending is None or _s256(verifier) != pending["challenge"]:
                self._send(400, json.dumps({"error": "invalid_grant"}).encode(), "application/json")
                return
            token = _id_token(pending["client_id"], pending["nonce"], pending["email"], ["responders"])
            self._send(200, json.dumps({"id_token": token, "token_type": "Bearer", "expires_in": 300}).encode(), "application/json")
            return
        self._send(404, json.dumps({"error": "not_found"}).encode(), "application/json")


def main() -> None:
    cert_dir = tempfile.mkdtemp(prefix="mock-idp-")
    cert, key = f"{cert_dir}/idp.crt", f"{cert_dir}/idp.key"
    pem = _PRIVATE.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    open(key, "wb").write(pem)
    subprocess.check_call(
        ["openssl", "req", "-x509", "-key", key, "-out", cert, "-days", "1", "-subj", "/CN=127.0.0.1",
         "-addext", "subjectAltName=IP:127.0.0.1"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    httpd = ThreadingHTTPServer(("127.0.0.1", 8443), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    print("Mock IdP ready")
    print(f"  issuer {ISSUER}")
    print(f"  SSL_CERT_FILE={cert}")
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    threading.Event().wait()


if __name__ == "__main__":
    main()
