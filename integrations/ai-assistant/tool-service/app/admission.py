"""Admission control (D14), lab-sized. There is no load balancer in front of
Bedrock, so fairness is enforced here: one stream per user, a small per-user
rate, and a per-tenant semaphore around every model invocation. Throttled
requests get an honest, immediate rejection - no silent downgrade."""
from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager

from .config import CFG


class BusyError(Exception):
    pass


class Admission:
    def __init__(self) -> None:
        self.user_streams: dict[str, int] = defaultdict(int)
        self.user_turns: dict[str, deque[float]] = defaultdict(deque)
        self.tenant_sem = asyncio.Semaphore(CFG.tenant_concurrent)

    def _allow_rate(self, sub: str) -> bool:
        window = self.user_turns[sub]
        now = time.monotonic()
        while window and now - window[0] > 60:
            window.popleft()
        if len(window) >= CFG.user_turns_per_minute:
            return False
        window.append(now)
        return True

    @asynccontextmanager
    async def acquire(self, sub: str):
        if self.user_streams[sub] >= 1:
            raise BusyError("one concurrent conversation per user")
        if not self._allow_rate(sub):
            raise BusyError("per-user rate limit, try again in a minute")
        self.user_streams[sub] += 1
        try:
            yield self
        finally:
            self.user_streams[sub] -= 1


ADMISSION = Admission()
