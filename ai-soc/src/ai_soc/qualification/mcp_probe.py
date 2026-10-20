from __future__ import annotations

import json
import os
import time
import urllib.request
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Protocol, cast

import boto3
from botocore.config import Config

from ai_soc.qualification.binding import DeploymentBinding
from ai_soc.qualification.mcp_models import LvMcpInputs
from ai_soc.qualification.mcp_protocol import run_probe_task_body
from ai_soc.qualification.models import McpTaskProbeConfig
from ai_soc.qualification.task_runtime import execution_deadline, load_task_config

_ACTIVE_FACT: ContextVar[tuple[str, list[dict[str, str]]] | None] = ContextVar(
    "lv_mcp_active_fact", default=None
)


class _Credentials(Protocol):
    @property
    def method(self) -> str: ...


class _BotoSession(Protocol):
    @property
    def region_name(self) -> str | None: ...
    def get_credentials(self) -> _Credentials | None: ...
    def client(self, service_name: str, *, region_name: str | None, config: Config) -> object: ...


def _response_field(value: object, key: str) -> object:
    return cast(dict[str, object], value).get(key) if isinstance(value, dict) else None


class _BoundedTaskClients:
    def __init__(self, region: str, deadline: float) -> None:
        self._session = cast(_BotoSession, boto3.Session(region_name=region))
        self._clients: dict[str, _DeadlineClient] = {}
        self.fact_requests: list[dict[str, str]] = []
        credentials = self._session.get_credentials()
        if credentials is None or credentials.method != "container-role":
            raise RuntimeError("MCP probe requires ECS task-role credentials")
        self._deadline = deadline

    def client(self, service_name: str) -> Any:
        if service_name in self._clients:
            return self._clients[service_name]
        client = self._session.client(
            service_name,
            region_name=self._session.region_name,
            config=Config(
                connect_timeout=5,
                read_timeout=5,
                retries={"total_max_attempts": 1, "mode": "standard"},
            ),
        )
        bounded = _DeadlineClient(client, self._deadline, self.fact_requests)
        self._clients[service_name] = bounded
        return bounded

    @contextmanager
    def fact_scope(self, fact_id: str):
        token = _ACTIVE_FACT.set((fact_id, self.fact_requests))
        try:
            yield
        finally:
            _ACTIVE_FACT.reset(token)


class _DeadlineClient:
    def __init__(self, client: Any, deadline: float, fact_requests: list[dict[str, str]]) -> None:
        self._client = client
        self._deadline = deadline
        self._fact_requests = fact_requests

    def __getattr__(self, name: str) -> Any:
        value = getattr(self._client, name)
        if not callable(value):
            return value

        def bounded(*args: object, **kwargs: object) -> object:
            if time.monotonic() >= self._deadline:
                raise TimeoutError("MCP qualification execution deadline expired")
            active = _ACTIVE_FACT.get()
            response = value(*args, **kwargs)
            if active is not None and name == "get_secret_value":
                fact_id, collector = active
                metadata = _response_field(response, "ResponseMetadata")
                request_id = _response_field(metadata, "RequestId")
                secret_id = kwargs.get("SecretId")
                if (
                    collector is self._fact_requests
                    and isinstance(request_id, str)
                    and request_id
                    and isinstance(secret_id, str)
                    and secret_id
                ):
                    self._fact_requests.append(
                        {
                            "fact_id": fact_id,
                            "operation": "GetSecretValue",
                            "request_id": request_id,
                        }
                    )
            if time.monotonic() >= self._deadline:
                raise TimeoutError("MCP qualification execution deadline expired")
            return response

        return bounded


def _task_arn() -> str:
    endpoint = os.environ.get("ECS_CONTAINER_METADATA_URI_V4")
    if not endpoint:
        raise RuntimeError("ECS task metadata endpoint is unavailable")
    request = urllib.request.Request(f"{endpoint.rstrip('/')}/task")
    with urllib.request.urlopen(request, timeout=5) as response:
        parsed: object = json.loads(response.read())
    payload = cast(dict[str, Any], parsed) if isinstance(parsed, dict) else {}
    arn = payload.get("TaskARN")
    if not isinstance(arn, str) or not arn:
        raise RuntimeError("ECS task metadata omitted task ARN")
    return arn


def main() -> int:
    raw_config = os.environ.get("LV_MCP_PROBE_CONFIG")
    if not raw_config:
        raise RuntimeError("probe task configuration is unavailable")
    config = load_task_config(raw_config, entrypoint="mcp")
    if not isinstance(config.scenario.parameters, McpTaskProbeConfig):
        raise RuntimeError("MCP task scenario is invalid")
    inputs: LvMcpInputs = config.scenario.parameters.inputs
    binding: DeploymentBinding = config.binding
    run_id = str(config.run_id)
    execution_budget, deadline = execution_deadline(config)
    clients = _BoundedTaskClients(binding.region, deadline)
    run_probe_task_body(
        inputs=inputs,
        clients=clients,
        binding=binding,
        task_arn=_task_arn(),
        run_id=run_id,
        session_id=str(config.session_id),
        invocation_id=str(config.invocation_id),
        wall_limit_seconds=execution_budget,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
