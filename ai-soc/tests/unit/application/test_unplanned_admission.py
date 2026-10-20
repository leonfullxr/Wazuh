from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest

from ai_soc.application.service import ApplicationService
from ai_soc.contracts.models import AdmissionGrant, AskRequest
from ai_soc.contracts.ports import AdmissionStore
from ai_soc.state.memory import MemoryState

NOW = datetime(2026, 9, 30, 12, tzinfo=UTC)
OWNER = "a" * 64


class _RejectingAdmission(AdmissionStore):
    def __init__(self) -> None:
        self.acquire_calls = 0

    async def acquire(
        self,
        owner_key: str,
        environment_id: str,
        operation: str,
        question_id: UUID,
        now: datetime,
    ) -> AdmissionGrant:
        self.acquire_calls += 1
        assert operation == "ingress"
        raise RuntimeError("owner request admission rejected")

    async def renew(self, grant: AdmissionGrant, now: datetime) -> AdmissionGrant:
        raise AssertionError("rejected requests cannot renew admission")

    async def release(self, grant: AdmissionGrant) -> None:
        return None


class _Clock:
    def now(self) -> datetime:
        return NOW

    def monotonic(self) -> float:
        return 0.0


@pytest.mark.asyncio
async def test_owner_admission_precedes_planning_and_external_work() -> None:
    admissions = _RejectingAdmission()
    planner = type(
        "Planner",
        (),
        {"plan": lambda *args, **kwargs: pytest.fail("planning ran before admission")},
    )()
    service = ApplicationService(
        clock=_Clock(),
        catalog=type("Catalog", (), {"manifest": lambda self: object()})(),  # type: ignore[arg-type]
        planner=planner,  # type: ignore[arg-type]
        site_policy=type(
            "SitePolicy",
            (),
            {"authorize": lambda *args: type("Site", (), {"policy_hash": "f" * 64})()},
        )(),  # type: ignore[arg-type]
        plans=object(),  # type: ignore[arg-type]
        admissions=admissions,
        question_admission=object(),  # type: ignore[arg-type]
        leases=object(),  # type: ignore[arg-type]
        budgets=object(),  # type: ignore[arg-type]
        completions=object(),  # type: ignore[arg-type]
        fetches=object(),  # type: ignore[arg-type]
        playbooks=object(),  # type: ignore[arg-type]
        judgment_engine=object(),  # type: ignore[arg-type]
        judgment_provider=object(),  # type: ignore[arg-type]
        finding_validator=object(),  # type: ignore[arg-type]
        telemetry=None,
        feedback_sink=object(),  # type: ignore[arg-type]
        feedback_store=MemoryState(),
        receipts=type("R", (), {"issue": lambda **kwargs: "token"})(),
        runtime=object(),  # type: ignore[arg-type]
        models=(),
    )
    request = AskRequest(environment_id="alpha", question="hello")
    principal = type("P", (), {"owner_key": OWNER, "issuer": "iss", "edge": "browser"})()
    with pytest.raises(RuntimeError, match="admission rejected"):
        await service.ask(request, principal)  # type: ignore[arg-type]
    assert admissions.acquire_calls == 1
