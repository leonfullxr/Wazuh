from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from threading import Lock
from typing import cast
from uuid import uuid4

import boto3
import pytest
from botocore.client import BaseClient
from botocore.config import Config


@dataclass(frozen=True)
class DynamoFixture:
    table: str
    clients: tuple[BaseClient, BaseClient]
    calls: list[tuple[str, dict[str, object]]]
    responses: list[tuple[str, dict[str, object]]]


@pytest.fixture
def dynamo_fixture() -> DynamoFixture:
    endpoint = os.environ.get("DYNAMODB_LOCAL_ENDPOINT")
    if endpoint != "http://127.0.0.1:8000":
        pytest.fail("integration runner must provide the task-owned DynamoDB Local loopback")

    table = f"socb3_{uuid4().hex}"
    calls: list[tuple[str, dict[str, object]]] = []
    responses: list[tuple[str, dict[str, object]]] = []
    lock = Lock()
    clients: list[BaseClient] = []
    for replica in range(2):
        client = cast(
            BaseClient,
            boto3.client(
                "dynamodb",
                region_name="us-east-1",
                endpoint_url=endpoint,
                aws_access_key_id=f"B3FIXTUREKEY{replica:02d}",
                aws_secret_access_key="B3-only-local-protocol-test-secret-0123456789",
                config=Config(
                    connect_timeout=2,
                    read_timeout=3,
                    retries={"total_max_attempts": 1, "mode": "standard"},
                    max_pool_connections=4,
                ),
            ),
        )

        # Botocore's operation event exposes the actual request parameters before transport.
        for method in ("GetItem", "TransactWriteItems"):
            client.meta.events.register(
                f"before-parameter-build.dynamodb.{method}",
                _dynamodb_call_recorder(method, calls, lock),
            )
        client.meta.events.register(
            "after-call.dynamodb.TransactWriteItems",
            _dynamodb_response_recorder("TransactWriteItems", responses, lock),
        )
        clients.append(client)

    created = False
    try:
        clients[0].create_table(
            TableName=table,
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        created = True
        clients[0].get_waiter("table_exists").wait(
            TableName=table,
            WaiterConfig={"Delay": 0, "MaxAttempts": 20},
        )
        yield DynamoFixture(
            table=table,
            clients=(clients[0], clients[1]),
            calls=calls,
            responses=responses,
        )
    finally:
        if created:
            clients[0].delete_table(TableName=table)
        for client in clients:
            client.close()


def _record(
    params: dict[str, object],
    operation: str,
    calls: list[tuple[str, dict[str, object]]],
    lock: Lock,
) -> None:
    with lock:
        calls.append((operation, dict(params)))


def _dynamodb_call_recorder(
    operation: str, calls: list[tuple[str, dict[str, object]]], lock: Lock
) -> Callable[..., None]:
    def capture(**event: object) -> None:
        params = event.get("params")
        if isinstance(params, dict):
            _record(cast(dict[str, object], params), operation, calls, lock)

    return capture


def _dynamodb_response_recorder(
    operation: str, responses: list[tuple[str, dict[str, object]]], lock: Lock
) -> Callable[..., None]:
    def capture(**event: object) -> None:
        parsed = event.get("parsed")
        if isinstance(parsed, dict):
            with lock:
                responses.append((operation, cast(dict[str, object], parsed)))

    return capture
