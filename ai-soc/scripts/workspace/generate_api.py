#!/usr/bin/env python3
"""Generate the workspace OpenAPI contract from the actual FastAPI router."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from fastapi import FastAPI, Request

from ai_soc.contracts.models import AuthorizedSite, SiteConfig, VerifiedPrincipal
from ai_soc.workspace.api.router import workspace_router
from ai_soc.workspace.api.runtime import WorkspaceRuntime


class _Policy:
    def authorized_sites(self, principal: VerifiedPrincipal) -> tuple[SiteConfig, ...]:
        return ()

    def authorize(self, principal: VerifiedPrincipal, environment_id: str) -> AuthorizedSite:
        raise RuntimeError("OpenAPI generation never authorizes requests")


async def _principal() -> VerifiedPrincipal:
    raise RuntimeError("OpenAPI generation never handles requests")


def _verify_csrf(_: Request, __: VerifiedPrincipal) -> None:
    return None


def render() -> bytes:
    app = FastAPI(title="AI SOC Workspace API", version="1.0.0", openapi_version="3.1.0")
    runtime = WorkspaceRuntime(lambda: "postgresql://unused", _Policy(), b"x" * 32)
    app.include_router(workspace_router(runtime, _principal, _verify_csrf), prefix="/v1/workspace")
    schema = app.openapi()
    # Keep OpenAPI's document-relative component references intact. Per-schema
    # $id values turn each component into a separate JSON Schema resource, where
    # nested #/components/schemas/... pointers no longer resolve.
    return (json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    target = Path(__file__).resolve().parents[2] / "contracts/workspace/v1/openapi.json"
    expected = render()
    if args.check:
        if not target.exists() or target.read_bytes() != expected:
            print(f"stale generated API contract: {target}")
            return 1
        return 0
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(expected)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
