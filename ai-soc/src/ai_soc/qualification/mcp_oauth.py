from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any, cast
from urllib.parse import urlsplit

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from pydantic import AnyHttpUrl, ValidationError

from ai_soc.qualification.mcp_models import (
    LvMcpInputs,
    ProbeContractError,
)

AUTH_NEGATIVES = ("wrong_resource", "wrong_issuer", "wrong_scope")
SUPPORTED_PROTOCOL = "2025-11-25"
_HTTPX_TRANSPORT_FACTORY: Any = None


def secret_string(client: Any, secret_id: str) -> str:
    response = client.get_secret_value(SecretId=secret_id)
    value = response.get("SecretString")
    if not isinstance(value, str) or not value:
        raise ValueError("referenced secret has no text value")
    return value


def is_scoped_secret_arn(value: str, *, region: str, account_id: str) -> bool:
    return bool(
        re.fullmatch(
            rf"arn:aws(?:-[a-z0-9-]+)?:secretsmanager:{re.escape(region)}:"
            rf"{re.escape(account_id)}:secret:qualification-mcp-[A-Za-z0-9/_+=.@-]+",
            value,
        )
    )


async def discover_auth_metadata(inputs: LvMcpInputs) -> dict[str, Any]:
    issuer_url = str(inputs.issuer).rstrip("/") + "/.well-known/openid-configuration"
    endpoint = urlsplit(str(inputs.endpoint))
    resource_url = f"{endpoint.scheme}://{endpoint.netloc}/.well-known/oauth-protected-resource/mcp"
    async with httpx.AsyncClient(
        timeout=inputs.timeout_seconds,
        trust_env=False,
        follow_redirects=False,
        transport=test_transport(),
    ) as client:
        oidc_response = await client.get(issuer_url)
        resource_response = await client.get(resource_url)
    if oidc_response.status_code != 200 or resource_response.status_code != 200:
        raise ValueError("OAuth discovery endpoints were not available")
    oidc = cast(dict[str, Any], oidc_response.json())
    protected = cast(dict[str, Any], resource_response.json())
    issuer_matches = oidc.get("issuer") == str(inputs.issuer).rstrip("/")
    token_endpoint_matches = oidc.get("token_endpoint") == str(inputs.token_endpoint)
    resource_matches = protected.get("resource") == str(inputs.resource)
    raw_servers = protected.get("authorization_servers")
    servers = cast(list[Any], raw_servers) if isinstance(raw_servers, list) else []
    normalized_servers: set[str] = {
        value.rstrip("/") for value in servers if isinstance(value, str)
    }
    auth_server_matches = raw_servers is None or (
        isinstance(raw_servers, list)
        and bool(servers)
        and len(normalized_servers) == len(servers)
        and str(inputs.issuer).rstrip("/") in normalized_servers
    )
    return {
        "passed": issuer_matches
        and token_endpoint_matches
        and resource_matches
        and auth_server_matches,
        "issuer_matches": issuer_matches,
        "token_endpoint_matches": token_endpoint_matches,
        "resource_matches": resource_matches,
        "authorization_server_matches": auth_server_matches,
        "authorization_server_advertised": bool(servers),
        "jwks_uri": oidc.get("jwks_uri"),
        "oidc_metadata_sha256": hashlib.sha256(canonical_json(oidc)).hexdigest(),
        "protected_resource_metadata_sha256": hashlib.sha256(canonical_json(protected)).hexdigest(),
    }


async def verify_negative_tokens(
    inputs: LvMcpInputs,
    discovery: Mapping[str, Any],
    tokens: Mapping[str, str],
) -> dict[str, dict[str, Any]]:
    issuer_jwks_uri = discovery.get("jwks_uri")
    if not isinstance(issuer_jwks_uri, str) or urlsplit(issuer_jwks_uri).scheme != "https":
        raise ValueError("OAuth discovery did not provide an HTTPS JWKS URI")
    if urlsplit(issuer_jwks_uri).hostname != urlsplit(str(inputs.issuer)).hostname:
        raise ValueError("OAuth JWKS host must match its pinned issuer host")
    trusted_keys = await _fetch_rsa_jwks(inputs, issuer_jwks_uri)
    alternate_uri = str(inputs.wrong_issuer.jwks_uri)
    if urlsplit(alternate_uri).hostname != urlsplit(str(inputs.wrong_issuer.issuer)).hostname:
        raise ValueError("wrong-issuer JWKS host must match its pinned issuer host")
    alternate_keys = await _fetch_rsa_jwks(inputs, alternate_uri)
    verified: dict[str, dict[str, Any]] = {}
    expected_resource = str(inputs.resource)
    expected_issuer = str(inputs.issuer).rstrip("/")
    alternate_issuer = str(inputs.wrong_issuer.issuer).rstrip("/")
    for name, token in tokens.items():
        header = jwt.get_unverified_header(token)
        if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
            raise ValueError(
                "negative OAuth token is not signed with the configured RS256 issuer key"
            )
        keys = alternate_keys if name == "wrong_issuer" else trusted_keys
        key = keys.get(header["kid"])
        if key is None:
            raise ValueError("negative OAuth token signing key is absent from issuer JWKS")
        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            options={
                "verify_iss": False,
                "verify_aud": False,
                "require": ["exp", "iss", "sub", "aud", "groups"],
            },
        )
        aud_claim = claims.get("aud")
        if isinstance(aud_claim, str):
            audiences: set[str] = {aud_claim}
        elif isinstance(aud_claim, list):
            aud_values = cast(list[Any], aud_claim)
            audiences = {value for value in aud_values if isinstance(value, str)}
        else:
            audiences = set()
        scopes = claims.get("scope", "")
        if not isinstance(scopes, str):
            raise ValueError("negative OAuth token has invalid scope claims")
        groups = claims.get("groups")
        group_values = cast(list[Any], groups) if isinstance(groups, list) else []
        if (
            not isinstance(claims.get("sub"), str)
            or not claims.get("sub")
            or not group_values
            or any(not isinstance(group, str) or not group for group in group_values)
            or len(set(group_values)) != len(group_values)
        ):
            raise ValueError("negative OAuth token is missing otherwise-valid identity claims")
        checks = {
            "wrong_resource": (
                claims.get("iss") == expected_issuer
                and expected_resource not in audiences
                and "soc:ask" in scopes.split()
            ),
            "wrong_issuer": (
                claims.get("iss") == alternate_issuer
                and audiences == {expected_resource}
                and "soc:ask" in scopes.split()
            ),
            "wrong_scope": (
                claims.get("iss") == expected_issuer
                and audiences == {expected_resource}
                and "soc:ask" not in scopes.split()
            ),
        }
        if not checks[name]:
            raise ValueError(f"{name} token does not isolate the intended OAuth claim negative")
        verified[name] = {"signature_valid": True, "intended_claim_negative": True}
    return verified


async def _fetch_rsa_jwks(inputs: LvMcpInputs, jwks_uri: str) -> dict[str, RSAPublicKey]:
    async with httpx.AsyncClient(
        timeout=inputs.timeout_seconds,
        trust_env=False,
        follow_redirects=False,
        transport=test_transport(),
    ) as client:
        response = await client.get(jwks_uri)
    if response.status_code != 200:
        raise ValueError("OAuth signing keys were unavailable")
    jwks = cast(dict[str, Any], response.json())
    from jwt.algorithms import RSAAlgorithm

    keys: dict[str, RSAPublicKey] = {}
    raw_keys = jwks.get("keys", [])
    if not isinstance(raw_keys, list):
        raise ValueError("OAuth JWKS did not contain a key list")
    for raw_entry in cast(list[Any], raw_keys):
        if not isinstance(raw_entry, dict):
            continue
        entry = cast(dict[str, Any], raw_entry)
        if entry.get("kty") != "RSA":
            continue
        if entry.get("use") not in (None, "sig") or entry.get("alg") not in (None, "RS256"):
            continue
        key_ops = entry.get("key_ops")
        if isinstance(key_ops, list) and "verify" not in key_ops:
            continue
        kid = entry.get("kid")
        if isinstance(kid, str):
            key = RSAAlgorithm.from_jwk(json.dumps(entry))
            if isinstance(key, RSAPublicKey):
                keys[kid] = key
    return keys


async def verify_id_token(
    inputs: LvMcpInputs, discovery: Mapping[str, Any], token: str
) -> dict[str, bool]:
    jwks_uri = discovery.get("jwks_uri")
    if not isinstance(jwks_uri, str):
        raise ValueError("OAuth discovery did not provide JWKS for the IdP ID token")
    keys = await _fetch_rsa_jwks(inputs, jwks_uri)
    header = jwt.get_unverified_header(token)
    kid = header.get("kid")
    if header.get("alg") != "RS256" or not isinstance(kid, str) or kid not in keys:
        raise ValueError("ID token does not use a trusted issuer signing key")
    claims = jwt.decode(
        token,
        keys[kid],
        algorithms=["RS256"],
        options={
            "verify_iss": False,
            "verify_aud": False,
            "require": ["exp", "iss", "sub", "aud", "groups"],
        },
    )
    aud = claims.get("aud")
    groups = claims.get("groups")
    group_values = cast(list[Any], groups) if isinstance(groups, list) else []
    valid = (
        claims.get("iss") == str(inputs.issuer).rstrip("/")
        and aud == inputs.client_id
        and isinstance(claims.get("sub"), str)
        and bool(claims.get("sub"))
        and isinstance(groups, list)
        and bool(group_values)
        and all(isinstance(group, str) and group for group in group_values)
        and len(set(group_values)) == len(group_values)
        and "soc:ask" in str(claims.get("scope", "")).split()
    )
    if not valid:
        raise ValueError("ID token does not isolate the authorization-type negative")
    return {"signature_valid": True, "client_audience_only": True, "identity_claims_valid": True}


async def verify_access_token(
    inputs: LvMcpInputs, discovery: Mapping[str, Any], token: str
) -> dict[str, bool]:
    jwks_uri = discovery.get("jwks_uri")
    if not isinstance(jwks_uri, str) or urlsplit(jwks_uri).scheme != "https":
        raise ValueError("OAuth discovery did not provide HTTPS JWKS for the access token")
    if urlsplit(jwks_uri).hostname != urlsplit(str(inputs.issuer)).hostname:
        raise ValueError("OAuth JWKS host must match the configured issuer host")
    keys = await _fetch_rsa_jwks(inputs, jwks_uri)
    header = jwt.get_unverified_header(token)
    kid = header.get("kid")
    if header.get("alg") != "RS256" or not isinstance(kid, str) or kid not in keys:
        raise ValueError("access token does not use a trusted issuer signing key")
    claims = jwt.decode(
        token,
        keys[kid],
        algorithms=["RS256"],
        options={
            "verify_iss": False,
            "verify_aud": False,
            "require": ["exp", "iss", "sub", "aud", "scope", "groups"],
        },
    )
    audience: object = claims.get("aud")
    audiences: set[str] = (
        {audience}
        if isinstance(audience, str)
        else {value for value in cast(list[Any], audience) if isinstance(value, str)}
        if isinstance(audience, list)
        else set()
    )
    groups: object = claims.get("groups")
    valid = (
        claims.get("iss") == str(inputs.issuer).rstrip("/")
        and claims.get("sub") == inputs.synthetic_subject
        and str(inputs.resource) in audiences
        and isinstance(groups, list)
        and any(isinstance(group, str) and group for group in cast(list[Any], groups))
        and "soc:ask" in str(claims.get("scope", "")).split()
    )
    if not valid:
        raise ValueError("access token does not match the synthetic user's OAuth contract")
    return {
        "signature_valid": True,
        "resource_audience_valid": True,
        "synthetic_subject_valid": True,
    }


async def probe_negatives(
    inputs: LvMcpInputs,
    valid_token: str,
    negative_tokens: Mapping[str, str],
    id_token: str,
    browser_cookie: str,
) -> dict[str, dict[str, Any]]:
    cases: dict[str, dict[str, Any]] = {}
    request_id = 7
    for name in AUTH_NEGATIVES:
        cases[name] = await _denial_case(
            inputs,
            headers={
                "Authorization": f"Bearer {negative_tokens[name]}",
                "Origin": origin_header(inputs.origin),
            },
            request_id=request_id,
        )
        request_id += 1
    cases["wrong_type"] = await _denial_case(
        inputs,
        headers={
            "Authorization": f"Bearer {id_token}",
            "Origin": origin_header(inputs.origin),
        },
        request_id=request_id,
    )
    request_id += 1
    cases["browser_cookie"] = await _denial_case(
        inputs,
        headers={
            "Cookie": browser_cookie,
            "Origin": origin_header(inputs.origin),
        },
        request_id=request_id,
    )
    if cases["browser_cookie"].get("error_code") is None:
        cases["browser_cookie"]["passed"] = (
            cases["browser_cookie"]["status_code"] == 401
            and "bearer" in str(cases["browser_cookie"].get("www_authenticate", "")).lower()
        )
    request_id += 1
    cases["origin"] = await _denial_case(
        inputs,
        headers={
            "Authorization": f"Bearer {valid_token}",
            "Origin": origin_header(inputs.disallowed_origin),
        },
        request_id=request_id,
    )
    request_id += 1
    async with httpx.AsyncClient(
        timeout=inputs.timeout_seconds,
        trust_env=False,
        transport=test_transport(),
        headers={
            "Authorization": f"Bearer {valid_token}",
            "Origin": origin_header(inputs.origin),
        },
    ) as client:
        response = await client.post(
            str(inputs.endpoint),
            json={
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "tools/list",
                "params": {},
            },
            headers={
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
                "MCP-Protocol-Version": "1900-01-01",
            },
        )
    cases["protocol_version"] = {
        "passed": response.status_code == 400,
        "status_code": response.status_code,
    }
    return cases


async def _denial_case(
    inputs: LvMcpInputs, *, headers: dict[str, str], request_id: int
) -> dict[str, Any]:
    async with httpx.AsyncClient(
        timeout=inputs.timeout_seconds,
        trust_env=False,
        follow_redirects=False,
        transport=test_transport(),
    ) as client:
        response = await client.post(
            str(inputs.endpoint),
            json={
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "initialize",
                "params": {
                    "protocolVersion": SUPPORTED_PROTOCOL,
                    "capabilities": {},
                    "clientInfo": {"name": "lv-mcp-negative-probe", "version": "1"},
                },
            },
            headers={
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
                **headers,
            },
        )
    try:
        error = response.json()
        error_object = cast(dict[str, Any], error) if isinstance(error, dict) else {}
        code = error_object.get("code")
    except (TypeError, ValueError):
        code = None
    denied = response.status_code in {400, 401, 403} and code in {
        "AUTH_REQUIRED",
        "AUTH_INVALID",
        "AUTH_EXPIRED",
        "SCOPE_DENIED",
        "ORIGIN_DENIED",
    }
    return {
        "passed": denied,
        "status_code": response.status_code,
        "error_code": code,
        "www_authenticate": response.headers.get("www-authenticate"),
    }


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def test_transport() -> httpx.AsyncBaseTransport | None:
    return _HTTPX_TRANSPORT_FACTORY() if _HTTPX_TRANSPORT_FACTORY is not None else None


def origin_header(value: AnyHttpUrl) -> str:
    parsed = urlsplit(str(value))
    return f"{parsed.scheme}://{parsed.netloc}"


def exception_summary(exc: Exception) -> str:
    if isinstance(exc, BaseExceptionGroup):
        nested = sorted(
            {
                exception_summary(item)
                for item in cast(tuple[BaseException, ...], cast(Any, exc).exceptions)
                if isinstance(item, Exception)
            }
        )
        return f"{type(exc).__name__}[{','.join(nested)}]"
    if isinstance(exc, ProbeContractError):
        return str(exc)
    if isinstance(exc, ValidationError):
        locations = sorted(
            ".".join(str(part) for part in error["loc"])
            for error in exc.errors(include_input=False)
        )
        return f"ValidationError[{','.join(locations)}]"
    return type(exc).__name__
