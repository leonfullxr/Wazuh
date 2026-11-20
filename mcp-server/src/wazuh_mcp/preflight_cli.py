"""Local operator entry point for verifying investigation prerequisites."""

import argparse
import asyncio
import json
import os
from pathlib import Path

from wazuh_mcp.api.wazuh_indexer import WazuhIndexerClient
from wazuh_mcp.clusters import read_cluster_connections
from wazuh_mcp.config import ConfigurationError, indexer_environment, validate_positive_int
from wazuh_mcp.preflight import PreflightLimits, investigation_preflight


def _reader(cluster: str | None) -> WazuhIndexerClient:
    # A missing explicitly configured file must never qualify an environment fallback.
    filename = os.getenv("WAZUH_CLUSTERS_FILE")
    if filename and not Path(filename).is_file():
        raise ConfigurationError("Configured cluster file was not found")
    default, connections = read_cluster_connections()
    selected = default if cluster is None else cluster
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
    return WazuhIndexerClient(host, port, user, password, verify_ssl=verify, timeout=timeout, use_ssl=ssl_enabled)


async def _run(args: argparse.Namespace) -> dict:
    try:
        reader = _reader(args.cluster)
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
                return await investigation_preflight(reader, args.tie_breaker, limits=limits)
            finally:
                await reader.close()
        except Exception:
            # Client exceptions can contain request URLs and operator input.
            reason = "Indexer verification or connection cleanup could not be completed"
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
    parser.add_argument("--cluster", help="Cluster ID from WAZUH_CLUSTERS_FILE; otherwise use the configured default")
    parser.add_argument("--timeout", type=_positive, default=defaults.seconds, help="Overall scan deadline in seconds")
    parser.add_argument("--max-documents", type=_positive, default=defaults.documents, help="Maximum alerts examined")
    parser.add_argument("--max-pages", type=_positive, default=defaults.pages, help="Maximum search pages")
    parser.add_argument("--max-bytes", type=_positive, default=defaults.bytes, help="Total response byte budget")
    parser.add_argument("--page-size", type=_positive, default=defaults.page_size, help="Documents per search page")
    result = asyncio.run(_run(parser.parse_args(argv)))
    print(json.dumps(result, sort_keys=True))
    return {"pass": 0, "fail": 1, "inconclusive": 2}[result["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
