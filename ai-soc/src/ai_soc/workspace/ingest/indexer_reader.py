"""Strict synchronous read-only scroll client for an authorized Wazuh pipeline identity."""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol, cast

import httpx


class IndexerError(RuntimeError):
    """Base class for safe, operator-visible indexer failures."""


class IndexerAuthError(IndexerError):
    """The configured pipeline identity was rejected and polling must stop."""


class IndexerUnavailable(IndexerError):
    """The indexer could not complete a bounded request."""


class TraversalRestart(IndexerError):
    """The active scroll is ambiguous or incomplete; restart its fixed window."""


class IncompleteTraversal(TraversalRestart):
    """A response was partial, malformed or inconsistent with its exact hit count."""


@dataclass(frozen=True, slots=True)
class IndexerHit:
    index_name: str
    doc_id: str
    source: dict[str, object]


@dataclass(frozen=True, slots=True)
class SearchPage:
    hits: tuple[IndexerHit, ...]
    exact_total: int


class Reader(Protocol):
    def iter_window(
        self,
        *,
        index_pattern: str,
        start: datetime,
        end: datetime,
        page_size: int,
        time_field: str,
    ) -> Iterator[SearchPage]: ...

    def count_window(
        self, *, index_pattern: str, start: datetime, end: datetime, time_field: str
    ) -> int: ...


class IndexerReader:
    """Use a preconfigured TLS-verified client and worker-only per-site auth."""

    def __init__(
        self,
        client: httpx.Client,
        *,
        auth: httpx.Auth | tuple[str, str] | None = None,
        scroll_keepalive: str = "2m",
        max_retries: int = 5,
        max_response_bytes: int = 16_777_216,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if scroll_keepalive != "2m":
            raise ValueError("scroll keepalive is fixed to the bounded two-minute setting")
        if not 0 <= max_retries <= 8:
            raise ValueError("max_retries must be in 0..8")
        if not 1024 <= max_response_bytes <= 16_777_216:
            raise ValueError("max_response_bytes must be in 1024..16777216")
        if client.follow_redirects:
            raise ValueError("pipeline indexer transport must reject redirects")
        self._client = client
        self._auth = auth
        self._scroll_keepalive = scroll_keepalive
        self._max_retries = max_retries
        self._max_response_bytes = max_response_bytes
        self._sleep = sleeper

    def iter_window(
        self,
        *,
        index_pattern: str,
        start: datetime,
        end: datetime,
        page_size: int,
        time_field: str = "timestamp",
    ) -> Iterator[SearchPage]:
        if not index_pattern or page_size < 1 or page_size > 10_000 or not time_field:
            raise ValueError("index pattern and a bounded positive page size are required")
        _validate_window(start, end)
        owned_scroll_id: str | None = None
        consumed = 0
        expected_total: int | None = None
        try:
            payload: dict[str, object] = {
                "size": page_size,
                "sort": ["_doc"],
                "track_total_hits": True,
                "query": {
                    "range": {
                        time_field: {
                            "gte": _utc_iso(start),
                            "lt": _utc_iso(end),
                        }
                    }
                },
            }
            response = self._request_json(
                "POST",
                f"/{index_pattern}/_search",
                query_params={"scroll": self._scroll_keepalive},
                body=payload,
                scroll_request=True,
            )
            owned_scroll_id = _scroll_id(response)
            page, expected_total = _page(response)
            consumed += len(page.hits)
            if page.hits:
                yield page
            while page.hits:
                response = self._request_json(
                    "POST",
                    "/_search/scroll",
                    body={"scroll": self._scroll_keepalive, "scroll_id": owned_scroll_id},
                    scroll_request=True,
                )
                owned_scroll_id = _scroll_id(response)
                page, response_total = _page(response)
                if response_total != expected_total:
                    raise IncompleteTraversal("scroll total changed during a fixed window")
                consumed += len(page.hits)
                if consumed > expected_total:
                    raise IncompleteTraversal("scroll returned more hits than its exact total")
                if page.hits:
                    yield page
            if consumed != expected_total:
                raise IncompleteTraversal("scroll ended before its exact total was exhausted")
        finally:
            if owned_scroll_id is not None:
                self._close_scroll(owned_scroll_id)

    def count_window(
        self,
        *,
        index_pattern: str,
        start: datetime,
        end: datetime,
        time_field: str = "timestamp",
    ) -> int:
        if not index_pattern or not time_field:
            raise ValueError("index pattern and time field are required")
        _validate_window(start, end)
        response = self._request_json(
            "POST",
            f"/{index_pattern}/_count",
            body={
                "query": {
                    "range": {
                        time_field: {
                            "gte": _utc_iso(start),
                            "lt": _utc_iso(end),
                        }
                    }
                }
            },
            scroll_request=False,
        )
        count = response.get("count")
        shards = response.get("_shards")
        timed_out = response.get("timed_out")
        if timed_out is not None and timed_out is not False:
            raise IncompleteTraversal("count response reported a timeout")
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise IncompleteTraversal("count response is malformed")
        if not isinstance(shards, dict) or not _all_shards_succeeded(
            cast(dict[str, object], shards)
        ):
            raise IncompleteTraversal("count response has incomplete shards")
        return count

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        scroll_request: bool,
        body: dict[str, object],
        query_params: dict[str, str] | None = None,
    ) -> dict[str, object]:
        for attempt in range(self._max_retries + 1):
            data: object = None
            try:
                with self._client.stream(
                    method,
                    path,
                    auth=self._auth,
                    params=query_params,
                    json=body,
                ) as response:
                    if response.status_code in {401, 403}:
                        raise IndexerAuthError("pipeline indexer authorization failed")
                    if response.status_code == 404 and scroll_request and path == "/_search/scroll":
                        raise TraversalRestart(
                            "indexer scroll context expired; restart fixed window"
                        )
                    if 500 <= response.status_code <= 599 and scroll_request:
                        raise TraversalRestart(
                            "indexer returned an ambiguous server error; restart fixed window"
                        )
                    if response.status_code == 429 or 500 <= response.status_code <= 599:
                        if attempt == self._max_retries:
                            raise IndexerUnavailable("indexer retry limit exhausted")
                        retry = True
                    elif response.status_code < 200 or response.status_code >= 300:
                        raise IndexerUnavailable(f"indexer returned HTTP {response.status_code}")
                    else:
                        response_bytes = bytearray()
                        for chunk in response.iter_bytes(chunk_size=65_536):
                            response_bytes.extend(chunk)
                            if len(response_bytes) > self._max_response_bytes:
                                raise IncompleteTraversal(
                                    "indexer response exceeded the byte limit"
                                )
                        retry = False
                        try:
                            data = cast(object, json.loads(response_bytes))
                        except (ValueError, UnicodeDecodeError) as exc:
                            raise IncompleteTraversal("indexer response is not valid JSON") from exc
            except httpx.TimeoutException as exc:
                if scroll_request:
                    raise TraversalRestart(
                        "indexer request timed out; restart fixed window"
                    ) from exc
                if attempt == self._max_retries:
                    raise IndexerUnavailable("indexer count request timed out") from exc
                self._sleep(_retry_delay(attempt))
                continue
            except httpx.TransportError as exc:
                if scroll_request:
                    raise TraversalRestart(
                        "indexer transport failed; restart fixed window"
                    ) from exc
                if attempt == self._max_retries:
                    raise IndexerUnavailable("indexer transport failed") from exc
                self._sleep(_retry_delay(attempt))
                continue
            if retry:
                self._sleep(_retry_delay(attempt))
                continue
            if not isinstance(data, dict):
                raise IncompleteTraversal("indexer response has an invalid shape")
            return cast(dict[str, object], data)
        raise IndexerUnavailable("indexer retry limit exhausted")

    def _close_scroll(self, scroll_id: str) -> None:
        try:
            response = self._client.request(
                "DELETE",
                "/_search/scroll",
                auth=self._auth,
                json={"scroll_id": [scroll_id]},
                timeout=5.0,
            )
        except httpx.HTTPError:
            return
        if response.status_code in {401, 403}:
            return


def _page(response: dict[str, object]) -> tuple[SearchPage, int]:
    if response.get("timed_out") is not False:
        raise IncompleteTraversal("indexer timed out or omitted timeout status")
    shards = response.get("_shards")
    if not isinstance(shards, dict) or not _all_shards_succeeded(cast(dict[str, object], shards)):
        raise IncompleteTraversal("indexer response has incomplete shards")
    hits_root = response.get("hits")
    if not isinstance(hits_root, dict):
        raise IncompleteTraversal("indexer hits are malformed")
    hits_mapping = cast(dict[str, object], hits_root)
    total = hits_mapping.get("total")
    if not isinstance(total, dict):
        raise IncompleteTraversal("indexer did not return an exact hit count")
    total_mapping = cast(dict[str, object], total)
    if total_mapping.get("relation") != "eq":
        raise IncompleteTraversal("indexer did not return an exact hit count")
    total_value = total_mapping.get("value")
    if isinstance(total_value, bool) or not isinstance(total_value, int) or total_value < 0:
        raise IncompleteTraversal("indexer exact hit count is malformed")
    hits_value = hits_mapping.get("hits")
    if not isinstance(hits_value, list):
        raise IncompleteTraversal("indexer hit list is malformed")
    hits: list[IndexerHit] = []
    for hit in cast(list[object], hits_value):
        if not isinstance(hit, dict):
            raise IncompleteTraversal("indexer hit is malformed")
        hit_mapping = cast(dict[str, object], hit)
        index_name = hit_mapping.get("_index")
        doc_id = hit_mapping.get("_id")
        source = hit_mapping.get("_source")
        if (
            not isinstance(index_name, str)
            or not index_name
            or not isinstance(doc_id, str)
            or not doc_id
            or not isinstance(source, dict)
        ):
            raise IncompleteTraversal("indexer hit identity or source is malformed")
        hits.append(IndexerHit(index_name, doc_id, cast(dict[str, object], source)))
    return SearchPage(tuple(hits), total_value), total_value


def _scroll_id(response: dict[str, object]) -> str:
    scroll_id = response.get("_scroll_id")
    if not isinstance(scroll_id, str) or not scroll_id:
        raise IncompleteTraversal("indexer did not return an owned scroll id")
    return scroll_id


def _all_shards_succeeded(shards: dict[str, object]) -> bool:
    total = shards.get("total")
    successful = shards.get("successful")
    failed = shards.get("failed")
    return (
        isinstance(total, int)
        and not isinstance(total, bool)
        and total >= 0
        and isinstance(successful, int)
        and not isinstance(successful, bool)
        and successful == total
        and isinstance(failed, int)
        and not isinstance(failed, bool)
        and failed == 0
    )


def _validate_window(start: datetime, end: datetime) -> None:
    if start.tzinfo is None or end.tzinfo is None:
        raise ValueError("window bounds must be timezone-aware")
    if start >= end:
        raise ValueError("window must be a non-empty [start, end) interval")


def _utc_iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat()


def _retry_delay(attempt: int) -> float:
    return min(300.0, 2.0**attempt)
