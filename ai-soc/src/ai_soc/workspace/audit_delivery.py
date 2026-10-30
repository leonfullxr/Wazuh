"""Acknowledged workspace audit delivery to SQS or an explicit local durable spool."""

from __future__ import annotations

import argparse
import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from uuid import uuid4

from ai_soc.telemetry.audit_delivery import SqsClient
from ai_soc.workspace.audit_message import audit_message, workspace_audit_json
from ai_soc.workspace.audit_outbox import AuditEvent, relay_audit_once
from ai_soc.workspace.db import site_transaction
from ai_soc.workspace.runtime import PipelineRuntime, load_pipeline_config


class SqsAuditSink:
    def __init__(self, client: SqsClient, *, queue_url: str) -> None:
        if not queue_url.startswith("https://"):
            raise ValueError("workspace audit queue URL must be HTTPS")
        self.client = client
        self.queue_url = queue_url

    def send(self, event: AuditEvent, /) -> bool:
        response = self.client.send_message(
            QueueUrl=self.queue_url,
            MessageBody=workspace_audit_json(audit_message(event)),
        )
        message_id = response.get("MessageId")
        return isinstance(message_id, str) and bool(message_id)


class FileAuditSink:
    """Qualification sink: one create-only event file, acknowledged after filesystem sync."""

    def __init__(self, directory: Path) -> None:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        mode = directory.lstat().st_mode
        if not stat.S_ISDIR(mode) or stat.S_IMODE(mode) & 0o077:
            raise ValueError("audit spool must be a private real directory")
        self.directory = directory

    def send(self, event: AuditEvent, /) -> bool:
        payload = workspace_audit_json(audit_message(event)).encode()
        destination = self.directory / f"{event.event_id}.json"
        temporary = self.directory / f".{uuid4()}.pending"
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as target:
                target.write(payload)
                target.flush()
                os.fsync(target.fileno())
            try:
                os.link(temporary, destination, follow_symlinks=False)
            except FileExistsError:
                existing = os.open(destination, os.O_RDONLY | os.O_NOFOLLOW)
                with os.fdopen(existing, "rb") as target:
                    if target.read(131_073) != payload:
                        raise ValueError(
                            "audit event identity conflicts with retained bytes"
                        ) from None
            directory = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)
        return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site", required=True)
    destination = parser.add_mutually_exclusive_group(required=True)
    destination.add_argument("--spool", type=Path, help="local durable qualification destination")
    destination.add_argument("--queue-url", help="existing HTTPS SQS audit queue")
    parser.add_argument("--max-events", type=int, default=1000)
    args = parser.parse_args()
    if not 1 <= args.max_events <= 100000:
        parser.error("max-events must be in1..100000")
    source = os.environ.get("WS_WORKER_CONFIG")
    if not source:
        parser.error("WS_WORKER_CONFIG is required")
    config = load_pipeline_config(Path(source))
    sites = frozenset(site.site_id for site in config.sites)
    if args.spool:
        sink = FileAuditSink(args.spool)
    else:
        from collections.abc import Callable

        import boto3

        factory = cast(Callable[..., object], vars(boto3)["client"])
        sink = SqsAuditSink(
            cast(SqsClient, factory("sqs", region_name=os.environ.get("AWS_REGION"))),
            queue_url=args.queue_url,
        )
    count = 0
    with PipelineRuntime(config) as runtime, runtime.connect() as conn:
        for _ in range(args.max_events):
            sent = relay_audit_once(
                conn, sink, datetime.now(UTC), site_id=args.site, authorized_sites=sites
            )
            if not sent:
                break
            count += sent
        with site_transaction(conn, args.site, sites):
            pending = conn.execute(
                "SELECT count(*) FROM audit_outbox WHERE site_id=%s AND sent_at IS NULL",
                (args.site,),
            ).fetchone()
            assert pending is not None
            outstanding = int(pending[0])
    print(
        json.dumps(
            {
                "acknowledged_events": count,
                "destination": "local_spool" if args.spool else "SQS",
                "outstanding_events": outstanding,
            }
        )
    )
    return 1 if outstanding else 0


if __name__ == "__main__":
    raise SystemExit(main())
