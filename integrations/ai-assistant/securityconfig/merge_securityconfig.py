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


def _saved_objects_patterns() -> list[str]:
    """Fresh list each call — PyYAML must not alias index_patterns across roles."""
    return [
        SAVED_OBJECTS_INDEX,
        f"{SAVED_OBJECTS_INDEX}*",
        f"{SAVED_OBJECTS_INDEX}_*",
        ".opensearch_dashboards",
        ".opensearch_dashboards*",
        ".opensearch_dashboards_*",
    ]
ENV_READER_USER = os.environ.get("WAI_ENV_READER_USER", "wazuh_ai_env_reader")
DASHBOARD_WRITER_USER = os.environ.get(
    "WAI_DASHBOARD_WRITER_USER", "wazuh_ai_dashboard_writer"
)
DASHBOARD_WRITER_PASSWORD_HASH = os.environ.get(
    "WAI_DASHBOARD_WRITER_PASSWORD_HASH",
    "$2b$12$OY5xZu30A.2oay3gJCEjQeNIsV/Bxyr.pAG5G7mwo9fB/5KVljfha",
)
ENV_READER_PASSWORD_HASH = os.environ.get(
    "WAI_ENV_READER_PASSWORD_HASH",
    "$2a$12$hsVmOpZVO2Kn7v8HO4eMseUBesSEHxVrKKnmeuqVBhm5l0qIzKkp6",
)
# Lab analyst users for auth-shim authinfo login (V3.6) — passwords match usernames
ANALYST1_PASSWORD_HASH = os.environ.get(
    "WAI_ANALYST1_PASSWORD_HASH",
    "$2b$12$SIWR6ujjAkVu.2iin1..Au1dYLtTzoZfpDzoGzbJvSOJLSRsnhrpi",
)
ANALYST_NO_OP_PASSWORD_HASH = os.environ.get(
    "WAI_ANALYST_NO_OP_PASSWORD_HASH",
    "$2b$12$dU4yGhiGnJqWi1aRK76p..fLxJXVhWw9CuBLnfIN/kaRqkFCKJLU6",
)
VIEWER1_PASSWORD_HASH = os.environ.get(
    "WAI_VIEWER1_PASSWORD_HASH",
    "$2b$12$JEHIXJLnJj.2pofPJ4gCvuWteXKHa6TV1/eMmY66oHs8S0Ty2ggFy",
)

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
                "index_patterns": ["wazuh-states-vulnerabilities-*"],
                "allowed_actions": [
                    "read",
                    "indices:admin/mappings/get",
                    "indices:admin/validate/query",
                    "indices:monitor/settings/get",
                    "indices:monitor/stats",
                ],
            },
            {
                "index_patterns": _saved_objects_patterns(),
                "allowed_actions": ["read"],
            },
        ],
    }
    roles["wazuh_ai_env_reader_role"] = {
        "reserved": False,
        "description": (
            "wazuh-ai connector edge: read-only alerts, C1 monitor grants, C3 ml predict (D42)"
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
                "index_patterns": ["wazuh-states-vulnerabilities-*"],
                "allowed_actions": [
                    "read",
                    "indices:admin/mappings/get",
                    "indices:admin/validate/query",
                    "indices:monitor/settings/get",
                    "indices:monitor/stats",
                ],
            },
            {
                "index_patterns": _saved_objects_patterns(),
                "allowed_actions": ["read"],
            },
        ],
    }
    # Actions v3.5 (D35): dashboard saved-objects writer — used by gateway executor only
    roles["wazuh_ai_dashboard_writer_role"] = {
        "reserved": False,
        "description": "wazuh-ai dashboard executor: write saved objects only (D35)",
        "cluster_permissions": ["cluster_composite_ops_ro"],
        "index_permissions": [
            {
                "index_patterns": _saved_objects_patterns(),
                "allowed_actions": [
                    "indices_all",
                ],
            },
        ],
    }
    # App-level operator role (confirm gate). Manager/AR executors use Wazuh API creds.
    roles["wazuh_ai_operator_role"] = {
        "reserved": False,
        "description": "wazuh-ai operator: may confirm proposed actions (D20)",
        "cluster_permissions": ["cluster_composite_ops_ro"],
        "index_permissions": [
            {
                "index_patterns": ["wazuh-alerts-*"],
                "allowed_actions": ["read"],
            },
        ],
    }
    roles["wazuh_ai_responder_role"] = {
        "reserved": False,
        "description": "wazuh-ai responder: may confirm manager/AR actions (R6.11)",
        "cluster_permissions": ["cluster_composite_ops_ro"],
        "index_permissions": [
            {
                "index_patterns": ["wazuh-alerts-*"],
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
    mapping["wazuh_ai_env_reader_role"] = {
        "reserved": False,
        "users": [ENV_READER_USER],
        "description": "Dashboard connector env-scoped reader (D42)",
    }
    mapping["wazuh_ai_operator_role"] = {
        "reserved": False,
        "backend_roles": ["wazuh_ai_operator"],
        "description": "JWT backend_roles claim -> wazuh-ai operator (confirm actions, D20)",
    }
    mapping["wazuh_ai_dashboard_writer_role"] = {
        "reserved": False,
        "users": [DASHBOARD_WRITER_USER],
        "description": "Dashboard executor internal user (D35)",
    }
    mapping["wazuh_ai_responder_role"] = {
        "reserved": False,
        "backend_roles": ["wazuh_ai_responder"],
        "description": "JWT backend_roles claim -> wazuh-ai responder (R6.11)",
    }
    map_path.write_text(yaml.safe_dump(mapping, sort_keys=False))

    users_path = workdir / "internal_users.yml"
    if users_path.exists():
        users = yaml.safe_load(users_path.read_text()) or {}
        users[ENV_READER_USER] = {
            "hash": ENV_READER_PASSWORD_HASH,
            "reserved": False,
            "description": "wazuh-ai environment reader for dashboard connector (D42)",
        }
        users[DASHBOARD_WRITER_USER] = {
            "hash": DASHBOARD_WRITER_PASSWORD_HASH,
            "reserved": False,
            # kibanauser backend role grants saved-object read/write on .kibana*
            # via the stock kibana_user role — the Dashboards _bulk_create API
            # (R6.9) needs it; without it saved-object writes 403. Note the
            # backend-role name is "kibanauser" (no underscore); the security
            # role it maps to is "kibana_user".
            "backend_roles": ["kibanauser"],
            "description": "wazuh-ai dashboard executor (D35) — gateway only",
        }
        users["analyst1"] = {
            "hash": ANALYST1_PASSWORD_HASH,
            "reserved": False,
            "description": "wazuh-ai lab analyst (V3.6)",
            "backend_roles": [
                "wazuh_ai_analyst",
                "wazuh_ai_operator",
                "wazuh_ai_responder",
            ],
        }
        users["analyst_no_op"] = {
            "hash": ANALYST_NO_OP_PASSWORD_HASH,
            "reserved": False,
            "description": "wazuh-ai lab analyst without operator role (V3.6)",
            "backend_roles": ["wazuh_ai_analyst"],
        }
        users["viewer1"] = {
            "hash": VIEWER1_PASSWORD_HASH,
            "reserved": False,
            "description": "lab user without wazuh-ai roles (negative tests, V3.6)",
        }
        users_path.write_text(yaml.safe_dump(users, sort_keys=False))

    print("merged: config.yml, roles.yml, roles_mapping.yml, internal_users.yml")


if __name__ == "__main__":
    main()
