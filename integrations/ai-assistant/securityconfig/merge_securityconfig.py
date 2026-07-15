#!/usr/bin/env python3
"""Merge the wazuh-ai additions into live indexer securityconfig files.

Uses text injection for config.yml (no PyYAML round-trip on the full file).
roles.yml and roles_mapping.yml are small enough for safe YAML load/dump.
"""
import os
import re
import sys
from pathlib import Path

import yaml

TENANT = "lab"
ISSUER = f"wazuh-ai-shim.{TENANT}"
AUDIENCE = f"wazuh-indexer.{TENANT}"
SAVED_OBJECTS_INDEX = os.environ.get("WAI_SAVED_OBJECTS_INDEX", ".kibana")

JWT_BLOCK_TEMPLATE = """\
      wazuh_ai_jwt_auth_domain:
        description: wazuh-ai turn JWTs minted by the auth shim (D30)
        http_enabled: true
        transport_enabled: false
        order: 0
        http_authenticator:
          type: jwt
          challenge: false
          config:
            signing_key: "{signing_key}"
            jwt_header: Authorization
            subject_key: sub
            roles_key: backend_roles
            required_issuer: {issuer}
            required_audience: {audience}
        authentication_backend:
          type: noop
"""


def _signing_key_literal(pubkey_pem: str) -> str:
    """Base64 PEM body on one line (no headers) — survives securityadmin round-trips."""
    lines = [
        line.strip()
        for line in pubkey_pem.strip().splitlines()
        if line and not line.startswith("-----")
    ]
    return "".join(lines)


def _merge_config(cfg_path: Path, signing_key: str) -> None:
    text = cfg_path.read_text()
    block = JWT_BLOCK_TEMPLATE.format(
        signing_key=signing_key,
        issuer=ISSUER,
        audience=AUDIENCE,
    )
    if "wazuh_ai_jwt_auth_domain:" in text:
        text = re.sub(
            r"      wazuh_ai_jwt_auth_domain:.*?(?=\n      [a-z_]+:|\n    authz:)",
            block.rstrip() + "\n",
            text,
            count=1,
            flags=re.DOTALL,
        )
    elif "\n    authz:" in text:
        text = text.replace("\n    authz:", "\n" + block + "    authz:", 1)
    else:
        raise SystemExit("config.yml: cannot find authz anchor for JWT domain injection")
    cfg_path.write_text(text)


def main() -> None:
    workdir = Path(sys.argv[1])
    pubkey_pem = Path(sys.argv[2]).read_text()
    signing_key = _signing_key_literal(pubkey_pem)

    _merge_config(workdir / "config.yml", signing_key)

    roles_path = workdir / "roles.yml"
    roles = yaml.safe_load(roles_path.read_text()) or {}
    roles["wazuh_ai_analyst_role"] = {
        "reserved": False,
        "description": (
            "wazuh-ai: read alerts, validate queries, index health, dashboard "
            "titles (C1), in-cluster embeddings (C3)"
        ),
        "cluster_permissions": [
            "cluster_composite_ops_ro",
            "cluster:admin/opensearch/ml/predict",
            "cluster:monitor/state",
            "cluster:monitor/health",
        ],
        "index_permissions": [
            {
                "index_patterns": ["wazuh-alerts-*"],
                "allowed_actions": [
                    "read",
                    "indices:admin/mappings/get",
                    "indices:admin/validate/query",
                    "indices:monitor/settings/get",
                    "indices:monitor/stats",
                ],
            },
            {
                "index_patterns": [SAVED_OBJECTS_INDEX, f"{SAVED_OBJECTS_INDEX}*"],
                "allowed_actions": ["read"],
            },
        ],
    }
    roles_path.write_text(yaml.safe_dump(roles, sort_keys=False))

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
