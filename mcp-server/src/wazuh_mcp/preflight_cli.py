"""Local operator entry point for verifying investigation prerequisites."""

import argparse
import asyncio
import ipaddress
import json
import os
import re
from pathlib import Path
from urllib.parse import urlsplit

from wazuh_mcp.api.wazuh_indexer import WazuhIndexerClient
from wazuh_mcp.clusters import CLUSTER_ID_PATTERN, read_cluster_connections
from wazuh_mcp.config import ConfigurationError, indexer_environment, validate_positive_int
from wazuh_mcp.preflight import PreflightLimits, investigation_preflight, valid_tie_breaker


class _TargetError(Exception):
    """A fixed, safe-to-display target configuration error."""


def _reader(cluster: str | None) -> tuple[WazuhIndexerClient, dict]:
    # A missing explicitly configured file must never qualify an environment fallback.
    filename = os.getenv("WAZUH_CLUSTERS_FILE")
    if filename == "":
        raise _TargetError("Empty WAZUH_CLUSTERS_FILE; unset it or set it to the server cluster file")
    if filename and not Path(filename).is_file():
        raise _TargetError("Configured cluster file was not found; set WAZUH_CLUSTERS_FILE to the server cluster file")
    if cluster is None and not filename and not Path("./config/clusters.json").is_file():
        raise _TargetError(
            "No implicit cluster file in this directory; use --cluster default for environment settings or set WAZUH_CLUSTERS_FILE"
        )
    default, connections = read_cluster_connections()
    selected = default if cluster is None else cluster
    if not isinstance(selected, str) or not CLUSTER_ID_PATTERN.fullmatch(selected):
        raise ConfigurationError("Invalid cluster ID")
    if selected == "default":
        env = indexer_environment()
        host = env["WAZUH_INDEXER_HOST"]
        port = env["WAZUH_INDEXER_PORT"]
        user = env["WAZUH_INDEXER_USER"]
        password = env["WAZUH_INDEXER_PASS"]
        ssl_enabled = env["WAZUH_INDEXER_SSL"]
        verify = (os.getenv("WAZUH_CA_BUNDLE", "").strip() or True) if env["WAZUH_INDEXER_VERIFY_SSL"] else False
        timeout = validate_positive_int(
            os.getenv("REQUEST_TIMEOUT_SECONDS", "30"), "REQUEST_TIMEOUT_SECONDS", max_val=300
        )
    elif selected in connections:
        config, prefix = connections[selected]
        if prefix:
            raise ConfigurationError("Cross-cluster search is unsupported")
        host = config.wazuh_indexer_host
        port = config.wazuh_indexer_port
        user = config.wazuh_indexer_user
        password = config.wazuh_indexer_pass
        ssl_enabled = config.wazuh_indexer_ssl
        verify = config.wazuh_indexer_verify_ssl
        timeout = config.request_timeout_seconds
    else:
        raise ConfigurationError("Unknown cluster")
    if not isinstance(host, str) or not host.strip():
        raise ConfigurationError("Indexer is not configured")
    reader = WazuhIndexerClient(host, port, user, password, verify_ssl=verify, timeout=timeout, use_ssl=ssl_enabled)
    # Use the actual client-normalized endpoint. Never report credentials or malformed input.
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in reader.host):
        raise _TargetError("Invalid Indexer host; use a hostname or IP and configure the port separately")
    try:
        endpoint = urlsplit(reader.scheme + "://" + reader.host)
        invalid = (
            not endpoint.hostname
            or endpoint.username is not None
            or endpoint.password is not None
            or endpoint.path
            or endpoint.query
            or endpoint.fragment
            or endpoint.port is not None
        )
    except ValueError:
        invalid = True
    if not invalid:
        try:
            ipaddress.ip_address(endpoint.hostname)
            invalid = "%" in endpoint.hostname
        except ValueError:
            labels = endpoint.hostname.rstrip(".").split(".")
            invalid = len(endpoint.hostname) > 253 or any(
                not label or len(label) > 63 or not re.fullmatch(r"[a-zA-Z0-9_-]+", label) for label in labels
            )
    if invalid:
        raise _TargetError("Invalid Indexer host; use a hostname or IP and configure the port separately")
    target = {
        "cluster_id": selected,
        "config_source": "environment" if selected == "default" else "file",
        "scheme": reader.scheme,
        "host": endpoint.hostname,
        "port": port,
    }
    return reader, target


async def _run(args: argparse.Namespace) -> dict:
    try:
        if not valid_tie_breaker(args.tie_breaker):
            return {
                "status": "fail",
                "reason": "Invalid tie-breaker field",
                "indices_checked": 0,
                "documents_checked": 0,
            }
        reader, target = _reader(args.cluster)
        target["tie_breaker"] = args.tie_breaker
    except _TargetError as exc:
        reason = str(exc)
    except (ConfigurationError, ValueError, OSError, TypeError):
        reason = "Check the selected cluster, direct Indexer connection and configuration"
    else:
        limits = PreflightLimits(
            seconds=args.timeout,
            pages=args.max_pages,
            documents=args.max_documents,
            bytes=args.max_bytes,
            page_size=args.page_size,
        )
        try:
            try:
                result = await investigation_preflight(reader, args.tie_breaker, limits=limits)
                result["target"] = target
                return result
            finally:
                await reader.close()
        except Exception:
            # Client exceptions can contain request URLs and operator input.
            reason = "Indexer verification or connection cleanup could not be completed"
            return {
                "status": "inconclusive",
                "reason": reason,
                "indices_checked": 0,
                "documents_checked": 0,
                "target": target,
            }
    return {"status": "inconclusive", "reason": reason, "indices_checked": 0, "documents_checked": 0}


def _positive(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def main(argv: list[str] | None = None) -> int:
    defaults = PreflightLimits()
    parser = argparse.ArgumentParser(
        prog="wazuh-mcp-preflight",
        description="Check investigation ordering and evidence access on one direct Indexer.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--tie-breaker", required=True, help="Candidate sortable field, such as event.id")
    parser.add_argument(
        "--cluster",
        help="Cluster ID; use default for environment settings. Without this option, a cluster file is required",
    )
    parser.add_argument("--timeout", type=_positive, default=defaults.seconds, help="Overall scan deadline in seconds")
    parser.add_argument("--max-documents", type=_positive, default=defaults.documents, help="Maximum alerts examined")
    parser.add_argument("--max-pages", type=_positive, default=defaults.pages, help="Maximum search pages")
    parser.add_argument("--max-bytes", type=_positive, default=defaults.bytes, help="Total response byte budget")
    parser.add_argument(
        "--page-size", type=_positive, default=defaults.page_size, help="Documents per search page (maximum 10000)"
    )
    result = asyncio.run(_run(parser.parse_args(argv)))
    print(json.dumps(result, sort_keys=True))
    return {"pass": 0, "fail": 1, "inconclusive": 2}[result["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
