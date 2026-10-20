from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from ai_soc.qualification.evidence import EvidencePaths
from ai_soc.qualification.network_canary import write_canary
from ai_soc.qualification.probe_health import run_probe

PATHS = EvidencePaths(
    app_prefix="qualification/",
    consumer_prefix="events/qualification/",
    map_key="qualification-maps/resource-map.json",
    input_prefix="qualification-inputs/",
)


class S3:
    def __init__(self) -> None:
        self.request: dict[str, Any] | None = None

    def put_object(self, **kwargs: Any) -> dict[str, str]:
        self.request = kwargs
        return {"VersionId": "test-version"}


def test_network_canary_is_conditional_kms_encrypted_and_task_attributed(tmp_path: Path) -> None:
    s3 = S3()
    ready = tmp_path / "ready"
    receipt = write_canary(
        s3,
        bucket="evidence",
        kms_key_arn="arn:aws:kms:eu-west-1:123456789012:key/key-id",
        evidence_paths=PATHS,
        session_id="session-1",
        run_id="run-2",
        placement="public-isolated",
        task_arn="arn:aws:ecs:eu-west-1:123456789012:task/cluster/task-id",
        account_id="123456789012",
        started_at=datetime(2026, 10, 8, 10, 0, tzinfo=UTC),
        ready_file=ready,
    )

    assert s3.request is not None
    assert s3.request["IfNoneMatch"] == "*"
    assert s3.request["ServerSideEncryption"] == "aws:kms"
    assert s3.request["SSEKMSKeyId"].endswith("key-id")
    assert s3.request["Key"].startswith("qualification/session-1/canary/public-isolated/run-2/")
    assert s3.request["Metadata"]["sha256"] == hashlib.sha256(s3.request["Body"]).hexdigest()
    assert json.loads(s3.request["Body"])["task_arn"] == receipt["task_arn"]
    assert ready.is_file()

    with pytest.raises(ValueError, match="placement"):
        write_canary(
            s3,
            bucket="evidence",
            kms_key_arn="key",
            evidence_paths=PATHS,
            session_id="session-1",
            run_id="run-2",
            placement="private",
            task_arn="task",
            account_id="123456789012",
        )


def test_probe_health_wrapper_serves_liveness_and_requires_preflight(tmp_path: Path) -> None:
    # Exercise the real health route and child exit handling without AWS or a container.
    import socket
    import threading
    import time
    import urllib.error
    import urllib.request

    ready = tmp_path / "ready"
    listener = socket.socket()
    listener.bind(("0.0.0.0", 8000))
    listener.close()
    result: list[int] = []
    child = (
        "import os,time; time.sleep(.15); "
        "open(os.environ['AI_SOC_PROBE_READY_FILE'],'w').close(); time.sleep(.4)"
    )
    worker = threading.Thread(
        target=lambda: result.append(
            run_probe(["python", "-c", child], timeout_seconds=3, ready_file=ready)
        ),
        daemon=True,
    )
    worker.start()
    for _ in range(100):
        try:
            urllib.request.urlopen("http://127.0.0.1:8000/health/live", timeout=0.1).close()
            break
        except (OSError, urllib.error.URLError):
            time.sleep(0.01)
    else:
        pytest.fail("health responder did not start")
    with pytest.raises(urllib.error.HTTPError) as not_ready:
        urllib.request.urlopen("http://127.0.0.1:8000/health/ready", timeout=0.2)
    assert not_ready.value.code == 503
    worker.join(timeout=2)
    assert result == [0]
