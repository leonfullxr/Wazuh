from __future__ import annotations

import os

import pytest


@pytest.mark.live
def test_live_boot_check_requires_dynamodb_local_endpoint() -> None:
    if os.environ.get("LIVE_BOOT_CHECK") != "1":
        pytest.skip("only enforced when invoked from make live-boot-check")
    if not os.environ.get("DYNAMODB_LOCAL_ENDPOINT"):
        pytest.fail("DYNAMODB_LOCAL_ENDPOINT must be set during live-boot-check")
