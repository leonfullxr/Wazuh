from __future__ import annotations

import os
import time

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, ConnectionClosedError, EndpointConnectionError


def main() -> None:
    client = boto3.client(
        "dynamodb",
        region_name="us-east-1",
        endpoint_url=os.environ.get("DYNAMODB_LOCAL_ENDPOINT", "http://127.0.0.1:8000"),
        aws_access_key_id="B3PROBEKEY",
        aws_secret_access_key="B3-local-readiness-probe-secret-0123456789",
        config=Config(connect_timeout=1, read_timeout=2, retries={"total_max_attempts": 1}),
    )
    deadline = time.monotonic() + 30
    try:
        while True:
            try:
                client.list_tables()
                print("list_tables succeeded against task-owned loopback DynamoDB Local")
                return
            except (EndpointConnectionError, ConnectionClosedError):
                if time.monotonic() >= deadline:
                    raise RuntimeError(
                        "task-owned DynamoDB Local did not become reachable"
                    ) from None
                time.sleep(0.25)
            except ClientError as error:
                code = error.response.get("Error", {}).get("Code")
                if code not in {"InternalServerError", "ServiceUnavailable", "RequestTimeout"}:
                    raise RuntimeError(f"DynamoDB Local readiness returned {code!r}") from None
                if time.monotonic() >= deadline:
                    raise RuntimeError(f"DynamoDB Local readiness remained {code!r}") from None
                time.sleep(0.25)
    finally:
        client.close()


if __name__ == "__main__":
    main()
