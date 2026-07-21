"""Admission control (D14), keyed per environment (D43)."""
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
    async def acquire(self, sub: str, *, env_scoped: bool = False):
        """Analyst turns: one stream + rate limit (D14). Connector/env turns skip
        both — ML Commons owns conversation pacing and may overlap requests."""
        if not env_scoped:
            if self.user_streams[sub] >= 1:
                raise BusyError("one concurrent conversation per user")
            if not self._allow_rate(sub):
                raise BusyError("per-user rate limit, try again in a minute")
            self.user_streams[sub] += 1
        try:
            yield self
        finally:
            if not env_scoped:
                self.user_streams[sub] -= 1


_ADMISSION: dict[str, Admission] = {}


def get_admission(env_id: str) -> Admission:
    if env_id not in _ADMISSION:
        _ADMISSION[env_id] = Admission()
    return _ADMISSION[env_id]


# Backward-compatible default for tests importing ADMISSION
ADMISSION = get_admission(CFG.tenant)
