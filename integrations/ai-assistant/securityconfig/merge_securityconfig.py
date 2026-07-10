#!/usr/bin/env python3
"""Merge the wazuh-ai additions into live indexer securityconfig files.

Adds, idempotently:
  config.yml         -> the wazuh_ai JWT auth domain (D11/D30), order 0,
                        challenge false so existing logins are untouched
  roles.yml          -> wazuh_ai_analyst_role: read-only on wazuh-alerts-*
                        plus mappings-get and validate-query (the veracity
                        pipeline needs both)
  roles_mapping.yml  -> backend_roles ["wazuh_ai_analyst"] -> that role

Usage: merge_securityconfig.py <dir-with-the-three-files> <public-key.pem>
"""
import sys
from pathlib import Path

import yaml

TENANT = "lab"
ISSUER = f"wazuh-ai-shim.{TENANT}"
AUDIENCE = f"wazuh-indexer.{TENANT}"


def main() -> None:
    workdir = Path(sys.argv[1])
    pubkey_pem = Path(sys.argv[2]).read_text()
    # The security plugin routes on the key's shape: a value starting with
    # -----BEGIN is parsed as an RSA/ECDSA PEM, anything else is treated as a
    # base64 HMAC secret. Base64-encoding the PEM lands in the HMAC branch and
    # every RS256 token fails verification, so pass the PEM through verbatim.
    signing_key = pubkey_pem

    # ---- config.yml: the JWT auth domain -----------------------------------
    cfg_path = workdir / "config.yml"
    cfg = yaml.safe_load(cfg_path.read_text())
    authc = cfg["config"]["dynamic"]["authc"]
    authc["wazuh_ai_jwt_auth_domain"] = {
        "description": "wazuh-ai turn JWTs minted by the auth shim (D30)",
        "http_enabled": True,
        "transport_enabled": False,
        "order": 0,
        "http_authenticator": {
            "type": "jwt",
            "challenge": False,
            "config": {
                "signing_key": signing_key,
                "jwt_header": "Authorization",
                "subject_key": "sub",
                "roles_key": "backend_roles",
                "required_issuer": ISSUER,
                # verify: with a list-valued aud claim, OpenSearch security
                # accepts the token if required_audience is one of the values.
                # Confirm on your indexer version.
                "required_audience": AUDIENCE,
            },
        },
        "authentication_backend": {"type": "noop"},
    }
    cfg_path.write_text(yaml.safe_dump(cfg, sort_keys=False))

    # ---- roles.yml: read-only analyst role ---------------------------------
    roles_path = workdir / "roles.yml"
    roles = yaml.safe_load(roles_path.read_text()) or {}
    roles["wazuh_ai_analyst_role"] = {
        "reserved": False,
        "description": "wazuh-ai: read alerts, get mappings, validate queries",
        "cluster_permissions": ["cluster_composite_ops_ro"],
        "index_permissions": [
            {
                "index_patterns": ["wazuh-alerts-*"],
                "allowed_actions": [
                    "read",
                    "indices:admin/mappings/get",
                    "indices:admin/validate/query",
                ],
            }
        ],
    }
    roles_path.write_text(yaml.safe_dump(roles, sort_keys=False))

    # ---- roles_mapping.yml --------------------------------------------------
    map_path = workdir / "roles_mapping.yml"
    mapping = yaml.safe_load(map_path.read_text()) or {}
    mapping["wazuh_ai_analyst_role"] = {
        "reserved": False,
        "backend_roles": ["wazuh_ai_analyst"],
        "description": "JWT backend_roles claim -> wazuh-ai analyst role",
    }
    map_path.write_text(yaml.safe_dump(mapping, sort_keys=False))

    print("merged: config.yml, roles.yml, roles_mapping.yml")


if __name__ == "__main__":
    main()
