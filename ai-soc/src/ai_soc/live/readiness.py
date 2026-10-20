"""Fail-closed readiness for live boot."""

from __future__ import annotations

import time
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout
from pathlib import Path
from threading import Lock

from ai_soc.content.catalog import ContentCatalog
from ai_soc.live.sealed import LiveSealedDocument

_PROBE_DEADLINE_SECONDS = 1.0


class LiveReadiness:
    def __init__(
        self,
        *,
        document: LiveSealedDocument,
        catalog: ContentCatalog,
        pack_dir: Path,
        dynamodb_probe: Callable[[], bool],
        dynamodb_cache_seconds: float = 3.0,
        probe_deadline_seconds: float = _PROBE_DEADLINE_SECONDS,
    ) -> None:
        self._document = document
        self._catalog = catalog
        self._pack_dir = pack_dir
        self._dynamodb_probe = dynamodb_probe
        self._dynamodb_cache_seconds = dynamodb_cache_seconds
        self._probe_deadline_seconds = probe_deadline_seconds
        self._dynamodb_cached: tuple[bool, float] | None = None
        self._probe_lock = Lock()
        self._probe_future: Future[bool] | None = None
        self._probe_completed_at: list[float | None] | None = None
        self._probe_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="readiness-ddb")

    def _dynamodb_ready(self) -> bool:
        now = time.monotonic()
        with self._probe_lock:
            if self._dynamodb_cached is not None and now < self._dynamodb_cached[1]:
                return self._dynamodb_cached[0]
            future = self._probe_future
            completion: list[float | None] | None = self._probe_completed_at
            if future is None:
                probe_completion: list[float | None] = [None]
                completion = probe_completion

                def probe() -> bool:
                    try:
                        return bool(self._dynamodb_probe())
                    finally:
                        probe_completion[0] = time.monotonic()

                future = self._probe_pool.submit(probe)
                self._probe_future = future
                self._probe_completed_at = completion
            if future.done():
                try:
                    ready = bool(future.result())
                except Exception:
                    ready = False
                completed_at = completion[0] if completion is not None else None
                if completed_at is None or now - completed_at >= self._dynamodb_cache_seconds:
                    ready = False
                    self._dynamodb_cached = None
                else:
                    self._dynamodb_cached = (
                        ready,
                        completed_at + self._dynamodb_cache_seconds,
                    )
                self._probe_future = None
                self._probe_completed_at = None
                return ready
        try:
            ready = bool(future.result(timeout=self._probe_deadline_seconds))
        except FuturesTimeout:
            with self._probe_lock:
                cached = self._dynamodb_cached
            return cached[0] if cached is not None and now < cached[1] else False
        except Exception:
            ready = False
        with self._probe_lock:
            completed_at = completion[0] if completion is not None else None
            if completed_at is None or time.monotonic() - completed_at >= (
                self._dynamodb_cache_seconds
            ):
                ready = False
                self._dynamodb_cached = None
            else:
                self._dynamodb_cached = (ready, completed_at + self._dynamodb_cache_seconds)
            if self._probe_future is future:
                self._probe_future = None
                self._probe_completed_at = None
        return ready

    def ready(self) -> bool:
        if not self._dynamodb_ready():
            return False
        if not self._pack_dir.is_dir():
            return False
        if self._catalog.manifest().pack_sha256 != self._document.provenance.pack_sha256:
            return False
        return True

    def close(self) -> None:
        with self._probe_lock:
            if self._probe_future is not None:
                self._probe_future.cancel()
            self._probe_future = None
            self._probe_completed_at = None
        self._probe_pool.shutdown(wait=False, cancel_futures=True)
