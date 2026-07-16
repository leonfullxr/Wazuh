"""Per-environment per-tier execution rate caps (R6.8)."""
from __future__ import annotations

import time
from collections import defaultdict


class TierRateLimiter:
    def __init__(self) -> None:
        self._events: dict[tuple[str, str], list[float]] = defaultdict(list)

    def allow(self, env_id: str, tier: str, limit: int, window_s: int = 3600) -> bool:
        """Return False when the cap is exceeded. limit <= 0 means uncapped."""
        if limit <= 0:
            return True
        key = (env_id, tier)
        now = time.monotonic()
        self._events[key] = [t for t in self._events[key] if now - t < window_s]
        if len(self._events[key]) >= limit:
            return False
        self._events[key].append(now)
        return True

    def reset_for_tests(self) -> None:
        self._events.clear()


LIMITER = TierRateLimiter()
