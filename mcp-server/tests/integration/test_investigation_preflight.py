import json
from urllib.parse import unquote

import httpx
import pytest

from wazuh_mcp.preflight import PreflightLimits, investigation_preflight


class Stream(httpx.AsyncByteStream):
    def __init__(self, data):
        self.data = json.dumps(data).encode()

    async def __aiter__(self):
        yield self.data


def response(status, *, json):
    return httpx.Response(status, stream=Stream(json))


class Backend:
    def __init__(self, docs=None):
        self.docs = docs if docs is not None else [("wazuh-alerts-a", "1", "alpha"), ("wazuh-alerts-b", "2", "beta")]
        self.indices = {"wazuh-alerts-a": "uuid-a", "wazuh-alerts-b": "uuid-b"}
        self.ccs_prefix = ""
        self.base_url = "https://indexer"
        self.client = httpx.AsyncClient(transport=httpx.MockTransport(self.handle))
        self.mapping = {"type": "keyword"}
        self.page = 0
        self.closed = False
        self.failure = None
        self.settings_calls = 0

    async def _ensure_initialized(self):
        pass

    def handle(self, request):
        path = request.url.path
        if path.endswith("/_settings"):
            if not path.startswith("/wazuh-alerts-*/"):
                name = path.split("/")[1]
                if self.failure == "settings_denied":
                    return response(403, json={})
                return response(200, json={name: {"settings": {"index": {"uuid": self.indices[name]}}}})
            self.settings_calls += 1
            indices = dict(self.indices)
            if self.failure == "rollover" and self.settings_calls > 1:
                indices["wazuh-alerts-c"] = "uuid-c"
            return response(200, json={k: {"settings": {"index": {"uuid": v}}} for k, v in indices.items()})
        if path.endswith("/_mapping"):
            return response(200, json={k: {"mappings": {"properties": {"tie": self.mapping}}} for k in self.indices})
        if path == "/_search/scroll" and request.method == "DELETE":
            self.closed = True
            return response(200, json={"succeeded": True})
        if "/_doc/" in path:
            index, doc_id = unquote(path).lstrip("/").split("/_doc/")
            if self.failure == "doc_denied":
                return response(403, json={})
            found = any(i == index and d == doc_id for i, d, _ in self.docs)
            return response(200 if found else 404, json={"_index": index, "_id": doc_id, "found": found, "_source": {}})
        if path.endswith("/_search") or path == "/_search/scroll":
            if path.endswith("/_search") and "scroll" not in request.url.params:
                return response(
                    200,
                    json={
                        "timed_out": False,
                        "_shards": {"total": 2, "successful": 2, "failed": 0},
                        "hits": {"hits": [{"sort": [123, "a"]}]},
                    },
                )
            self.page += 1
            rows = self.docs[self.page - 1 : self.page]
            hits = [
                {"_index": i, "_id": d, "_source": {"tie": v}, "fields": {"tie": v if isinstance(v, list) else [v]}}
                for i, d, v in rows
            ]
            body = {
                "_scroll_id": "secret-scroll",
                "timed_out": False,
                "_shards": {"total": 2, "successful": 2, "failed": 0},
                "hits": {"total": {"value": len(self.docs), "relation": "eq"}, "hits": hits},
            }
            if self.failure == "partial":
                body["_shards"]["successful"] = 1
            if self.failure == "timed_out":
                body["timed_out"] = True
            if self.failure == "missing_total":
                body["hits"]["total"]["relation"] = "gte"
            return response(200, json=body)
        raise AssertionError(f"Unexpected request: {request.method} {path}")


@pytest.mark.asyncio
async def test_exhausts_every_index_and_cleans_scroll():
    backend = Backend()
    result = await investigation_preflight(backend, "tie")
    assert result["status"] == "pass"
    assert result["indices_checked"] == 2
    assert result["documents_checked"] == 2
    assert backend.page == 3 and backend.closed
    assert "alpha" not in json.dumps(result)
    await backend.client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "values, reason",
    [
        (["same", "same"], "unique"),
        (["one", None], "missing"),
        (["one", "  "], "empty"),
        (["one", ["two", "three"]], "multi-valued"),
        (["one", ["two"]], "multi-valued"),
    ],
)
async def test_observed_data_violations_fail(values, reason):
    backend = Backend([("wazuh-alerts-a", "1", values[0]), ("wazuh-alerts-b", "2", values[1])])
    result = await investigation_preflight(backend, "tie")
    assert result["status"] == "fail" and reason in result["reason"]
    assert backend.closed
    await backend.client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["partial", "timed_out", "missing_total", "rollover", "doc_denied"])
async def test_incomplete_evidence_is_inconclusive(failure):
    backend = Backend()
    backend.failure = failure
    assert (await investigation_preflight(backend, "tie"))["status"] == "inconclusive"
    assert backend.closed
    await backend.client.aclose()


@pytest.mark.asyncio
async def test_zero_documents_and_budgets_are_inconclusive():
    empty = Backend([])
    assert (await investigation_preflight(empty, "tie"))["status"] == "inconclusive"
    assert empty.closed
    await empty.client.aclose()
    limited = Backend()
    result = await investigation_preflight(limited, "tie", limits=PreflightLimits(documents=1))
    assert result["status"] == "inconclusive"
    assert limited.closed
    await limited.client.aclose()


@pytest.mark.asyncio
async def test_mapping_must_have_doc_values():
    backend = Backend()
    backend.mapping = {"type": "keyword", "doc_values": False}
    assert (await investigation_preflight(backend, "tie"))["status"] == "fail"
    await backend.client.aclose()


@pytest.mark.asyncio
async def test_concrete_settings_permission_is_required():
    backend = Backend()
    backend.failure = "settings_denied"
    result = await investigation_preflight(backend, "tie")
    assert result["status"] == "inconclusive"
    assert "permission" in result["reason"].lower()
    await backend.client.aclose()


@pytest.mark.asyncio
async def test_source_path_ambiguity_is_inconclusive():
    backend = Backend([("wazuh-alerts-a", "1", "one")])
    backend.mapping = {"type": "date"}
    assert (await investigation_preflight(backend, "tie"))["status"] == "inconclusive"
    await backend.client.aclose()


@pytest.mark.asyncio
async def test_byte_and_page_budgets_are_inconclusive():
    for limits in (PreflightLimits(bytes=1), PreflightLimits(pages=1)):
        backend = Backend()
        result = await investigation_preflight(backend, "tie", limits=limits)
        assert result["status"] == "inconclusive"
        if backend.page:
            assert backend.closed
        await backend.client.aclose()


@pytest.mark.asyncio
async def test_cancellation_releases_scroll():
    import asyncio

    backend = Backend()
    original = backend._ensure_initialized
    entered = asyncio.Event()
    calls = 0

    async def pause_after_scroll():
        nonlocal calls
        calls += 1
        if calls == 6:
            entered.set()
            await asyncio.Event().wait()
        await original()

    backend._ensure_initialized = pause_after_scroll
    task = asyncio.create_task(investigation_preflight(backend, "tie"))
    await asyncio.wait_for(entered.wait(), 1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert backend.closed
    await backend.client.aclose()


@pytest.mark.asyncio
async def test_deadline_releases_scroll():
    import asyncio

    backend = Backend()
    calls = 0

    async def pause_after_scroll():
        nonlocal calls
        calls += 1
        if calls == 6:
            await asyncio.Event().wait()

    backend._ensure_initialized = pause_after_scroll
    result = await investigation_preflight(backend, "tie", limits=PreflightLimits(seconds=0.01))
    assert result["status"] == "inconclusive"
    assert backend.closed
    await backend.client.aclose()
