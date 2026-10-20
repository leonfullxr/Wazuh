#!/usr/bin/env python3
"""Send one synthetic OTLP gRPC span to the private Compose collector."""

from __future__ import annotations

from typing import Protocol, cast

import grpc
from opentelemetry.proto.collector.trace.v1 import trace_service_pb2, trace_service_pb2_grpc
from opentelemetry.proto.common.v1 import common_pb2
from opentelemetry.proto.resource.v1 import resource_pb2
from opentelemetry.proto.trace.v1 import trace_pb2


class TraceService(Protocol):
    def Export(self, request: object, *, timeout: float) -> object: ...


def main() -> int:
    now = 1_797_000_000_000_000_000
    request = trace_service_pb2.ExportTraceServiceRequest(
        resource_spans=[
            trace_pb2.ResourceSpans(
                resource=resource_pb2.Resource(
                    attributes=[
                        common_pb2.KeyValue(
                            key="service.name",
                            value=common_pb2.AnyValue(string_value="ai-soc-fixture-probe"),
                        )
                    ]
                ),
                scope_spans=[
                    trace_pb2.ScopeSpans(
                        spans=[
                            trace_pb2.Span(
                                trace_id=bytes.fromhex("a" * 32),
                                span_id=bytes.fromhex("b" * 16),
                                name="soc-local-protocol-probe",
                                kind=trace_pb2.Span.SPAN_KIND_INTERNAL,
                                start_time_unix_nano=now,
                                end_time_unix_nano=now + 1_000_000,
                            )
                        ]
                    )
                ],
            )
        ]
    )
    with grpc.insecure_channel("adot-collector:4317") as channel:
        grpc.channel_ready_future(channel).result(timeout=10)
        service = cast(TraceService, trace_service_pb2_grpc.TraceServiceStub(channel))
        service.Export(request, timeout=10)
    print("otlp_export=acknowledged spans=1")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
