"""Per-IP and per-user exchange throttling (V3.6 follow-up)."""
from __future__ import annotations

import time
from collections import defaultdict, deque


class ExchangeRateLimiter:
    def __init__(self, *, per_user_per_minute: int, per_ip_per_minute: int) -> None:
        self._per_user = per_user_per_minute
        self._per_ip = per_ip_per_minute
        self._user_hits: dict[str, deque[float]] = defaultdict(deque)
        self._ip_hits: dict[str, deque[float]] = defaultdict(deque)

    def _prune(self, window: deque[float], now: float) -> None:
        while window and now - window[0] > 60:
            window.popleft()

    def allow(self, *, client_ip: str, username: str, env_id: str) -> bool:
        now = time.monotonic()
        user_key = f"{env_id}:{username}"
        ip_key = client_ip or "unknown"
        user_window = self._user_hits[user_key]
        ip_window = self._ip_hits[ip_key]
        self._prune(user_window, now)
        self._prune(ip_window, now)
        if len(user_window) >= self._per_user or len(ip_window) >= self._per_ip:
            return False
        user_window.append(now)
        ip_window.append(now)
        return True
