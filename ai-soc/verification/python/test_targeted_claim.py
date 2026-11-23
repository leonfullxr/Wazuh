"""Target validation before database access."""

from datetime import UTC, datetime, timedelta

import pytest

from ai_soc.workspace.jobs import claim_job
from ai_soc.workspace.worker import run_once


@pytest.mark.parametrize("target", [True, False, "1", 0, -1, 9223372036854775808])
def test_invalid_target_fails_before_database_access(target):
    with pytest.raises(ValueError):
        claim_job(
            object(),
            worker_id="w",
            now=datetime.now(UTC),
            lease=timedelta(seconds=1),
            site_id="s",
            authorized_sites=frozenset({"s"}),
            target_job_id=target,
        )
    with pytest.raises(ValueError):
        run_once(object(), worker_id="w", site_ids=frozenset({"s"}), target_job_id=target)


@pytest.mark.parametrize(
    "sites,batch", [(frozenset(), 1), (frozenset({"a", "b"}), 1), (frozenset({"a"}), 2)]
)
def test_target_requires_one_site_and_one_job(sites, batch):
    with pytest.raises(ValueError):
        run_once(object(), worker_id="w", site_ids=sites, batch_size=batch, target_job_id=1)


@pytest.mark.parametrize("target", [1, 9223372036854775807])
def test_bigint_bounds_pass_validation(monkeypatch, target):
    from ai_soc.workspace import jobs

    class ReachedSiteCheck(Exception):
        pass

    def reached(*_args):
        raise ReachedSiteCheck

    monkeypatch.setattr(jobs, "_require_site", reached)
    with pytest.raises(ReachedSiteCheck):
        claim_job(
            object(),
            worker_id="w",
            now=datetime.now(UTC),
            lease=timedelta(seconds=1),
            site_id="s",
            authorized_sites=frozenset({"s"}),
            target_job_id=target,
        )
