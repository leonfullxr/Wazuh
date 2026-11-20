"""
Active-response and Wazuh-API correctness tests (B3 blocker cluster).

Covers the tool-correctness bugs where the client either could never succeed or
returned a misleading success against a stock Wazuh deployment.
"""

import pytest

from wazuh_mcp.api.wazuh_client import WazuhClient
from wazuh_mcp.config import WazuhConfig


def _client(monkeypatch=None):
    return WazuhClient(WazuhConfig(wazuh_host="localhost", wazuh_user="u", wazuh_pass="p", verify_ssl=False))


class TestGenericActiveResponse:
    @pytest.mark.asyncio
    async def test_command_without_bang_is_normalized_and_accepted(self):
        client = _client()
        sent = {}

        async def fake_exec(data):
            sent.update(data)
            return {"data": {"total_affected_items": 1, "total_failed_items": 0, "failed_items": []}}

        client.execute_active_response = fake_exec
        # A bare command name is normalized before the allowlist check.
        await client.run_active_response("001", "restart-wazuh")
        assert sent["command"] == "!restart-wazuh"

    @pytest.mark.asyncio
    async def test_bang_form_still_accepted(self):
        client = _client()
        sent = {}

        async def fake_exec(data):
            sent.update(data)
            return {"data": {"total_affected_items": 1, "total_failed_items": 0, "failed_items": []}}

        client.execute_active_response = fake_exec
        await client.run_active_response("001", "!host-isolation")
        assert sent["command"] == "!host-isolation"

    @pytest.mark.asyncio
    async def test_unknown_command_still_rejected(self):
        client = _client()
        with pytest.raises(ValueError, match="Unknown active response command"):
            await client.run_active_response("001", "rm-rf-slash")

    def test_validator_accepts_optional_bang(self):
        from wazuh_mcp.security import validate_active_response_command

        assert validate_active_response_command("firewall-drop") == "firewall-drop"
        assert validate_active_response_command("!firewall-drop") == "!firewall-drop"


class TestDisableUserPayload:
    @pytest.mark.asyncio
    async def test_disable_user_sets_dstuser_alert(self):
        client = _client()
        sent = {}

        async def fake_exec(data):
            sent.update(data)
            return {"data": {"total_affected_items": 1, "total_failed_items": 0, "failed_items": []}}

        client.execute_active_response = fake_exec
        await client.disable_user("001", "attacker")
        # Stock disable-account reads the target from alert.data.dstuser.
        assert sent["alert"]["data"]["dstuser"] == "attacker"
        assert "attacker" in sent["arguments"]


class TestRollbackNeverReblocks:
    @pytest.mark.asyncio
    async def test_firewall_allow_refuses_without_undo_command(self, monkeypatch):
        monkeypatch.delenv("WAZUH_AR_FIREWALL_UNDO_COMMAND", raising=False)
        client = _client()
        # Must NOT invoke active response (which would re-block).
        called = False

        async def fake_exec(data):
            nonlocal called
            called = True
            return {}

        client.execute_active_response = fake_exec
        with pytest.raises(ValueError, match="re-block|undo"):
            await client.firewall_allow("001", "10.0.0.5")
        assert called is False

    @pytest.mark.asyncio
    async def test_firewall_allow_uses_configured_undo_command(self, monkeypatch):
        monkeypatch.setenv("WAZUH_AR_FIREWALL_UNDO_COMMAND", "firewall-undrop")
        client = _client()
        sent = {}

        async def fake_exec(data):
            sent.update(data)
            return {"data": {"total_affected_items": 1, "total_failed_items": 0, "failed_items": []}}

        client.execute_active_response = fake_exec
        await client.firewall_allow("001", "10.0.0.5")
        assert sent["command"] == "!firewall-undrop"  # normalized with leading !
        assert sent["alert"]["data"]["srcip"] == "10.0.0.5"


class TestManagerLogSearch:
    @pytest.mark.asyncio
    async def test_search_manager_logs_uses_search_param(self):
        client = _client()
        captured = {}

        async def fake_request(method, endpoint, **kwargs):
            captured["endpoint"] = endpoint
            captured["params"] = kwargs.get("params")
            return {"data": {"affected_items": []}}

        client._request = fake_request
        await client.search_manager_logs("error something", 50)
        # Free text must go through `search`, not `q` (which needs field=value syntax).
        assert "search" in captured["params"]
        assert "q" not in captured["params"]


class TestCheckFileQuarantineRoute:
    @pytest.mark.asyncio
    async def test_uses_per_agent_syscheck_route(self):
        client = _client()
        captured = {}

        async def fake_request(method, endpoint, **kwargs):
            captured["endpoint"] = endpoint
            return {"data": {"affected_items": []}}

        client._request = fake_request
        await client.check_file_quarantine("007", "/etc/passwd")
        assert captured["endpoint"] == "/syscheck/007"


class TestISO27001Scoring:
    def _client_with_indexer(self):
        return WazuhClient(
            WazuhConfig(
                wazuh_host="localhost",
                wazuh_user="u",
                wazuh_pass="p",
                verify_ssl=False,
                wazuh_indexer_host="localhost",
                wazuh_indexer_user="i",
                wazuh_indexer_pass="i",
            )
        )

    async def _run_dashboard(self, client, *, stats_events, vulns_raise):
        async def fake_request(method, endpoint, **kwargs):
            if endpoint == "/agents":
                return {"data": {"affected_items": [{"id": "001", "name": "web-01"}], "total_affected_items": 1, "total_failed_items": 0}}
            if endpoint.startswith("/sca/"):
                return {"data": {"affected_items": []}}
            if endpoint == "/manager/stats/analysisd":
                # Real Wazuh shape: stats live under data.affected_items[0]
                return {"data": {"affected_items": [{"total_events_decoded": stats_events}]}}
            return {"data": {"affected_items": []}}

        async def fake_get_alerts(**kwargs):
            return {"data": {"affected_items": [], "total_affected_items": 0}}

        async def fake_vulns(**kwargs):
            if vulns_raise:
                raise RuntimeError("indexer down")
            return {"data": {"affected_items": [], "completeness": {"complete": True, "reasons": []}}}

        client._request = fake_request
        client.get_alerts = fake_get_alerts
        client._indexer_client.get_vulnerabilities = fake_vulns
        result = await client.get_iso27001_dashboard()
        return {c["control_id"]: c for c in result["data"]["controls"]}

    @pytest.mark.asyncio
    async def test_logging_control_reads_nested_stats(self):
        """A.8.15 must read data.affected_items[0].total_events_decoded, not data.* -
        a direct read would always see 0 and report a false no_data gap."""
        client = self._client_with_indexer()
        controls = await self._run_dashboard(client, stats_events=12345, vulns_raise=False)
        a815 = controls["A.8.15"]
        assert a815["status"] == "active"
        assert a815["evidence_count"] == 12345

    @pytest.mark.asyncio
    async def test_indexer_failure_scores_vuln_control_as_no_data_not_100(self):
        """An Indexer outage must not yield a perfect vulnerability score with high confidence."""
        client = self._client_with_indexer()
        controls = await self._run_dashboard(client, stats_events=1, vulns_raise=True)
        a88 = controls["A.8.8"]
        assert a88["status"] == "no_data"
        assert a88["score"] is None
        assert a88["confidence"] == "none"

    @pytest.mark.asyncio
    async def test_successful_zero_vuln_query_is_full_compliance(self):
        """A successful query returning zero vulns is legitimately 100/pass/high."""
        client = self._client_with_indexer()
        controls = await self._run_dashboard(client, stats_events=1, vulns_raise=False)
        a88 = controls["A.8.8"]
        assert a88["status"] == "pass"
        assert a88["score"] == 100
        assert a88["confidence"] == "high"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

class TestISOCompleteness:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("total,extra,reason", [
        (None, {}, "unknown_total"), ("1", {}, "unknown_total"),
        ({"value": 1, "relation": "gte"}, {}, "unknown_total"),
        (600, {}, "page_truncated"), (1, {"timed_out": True}, "search_incomplete"),
        (1, {"_shards": {"failed": 1}}, "search_incomplete"),
        (1, {"_clusters": {"partial": 1}}, "search_incomplete"),
        ({"value": 1, "relation": "eq"}, {}, None),
    ])
    async def test_indexer_completeness(self, total, extra, reason):
        client = TestISO27001Scoring()._client_with_indexer()._indexer_client
        async def search(*args, **kwargs):
            return {"hits": {"total": total, "hits": [{"_source": {}}]}, **extra}
        client._search = search
        data = (await client.get_vulnerabilities(agent_id="001"))["data"]
        assert data["completeness"]["complete"] is (reason is None)
        if reason:
            assert reason in data["completeness"]["reasons"]

    async def dashboard(self, agent_ids, results, *, total=None, failed=0, agent_id=None):
        client = TestISO27001Scoring()._client_with_indexer()
        async def request(method, endpoint, **kwargs):
            if endpoint == "/agents":
                return {"data": {"affected_items": [{"id": a} for a in agent_ids],
                                 "total_affected_items": total, "total_failed_items": failed}}
            return {"data": {"affected_items": []}}
        async def alerts(**kwargs):
            return {"data": {"affected_items": []}}
        async def search(index, query, size):
            tid = query["bool"]["must"][0]["term"]["agent.id"]
            value = results[tid]
            if isinstance(value, Exception):
                raise value
            return value
        client._request = request
        client.get_alerts = alerts
        client._indexer_client._search = search
        return client, (await client.get_iso27001_dashboard(agent_id))["data"]

    @staticmethod
    def hits(count, total=None):
        return {"hits": {"total": count if total is None else total,
                         "hits": [{"_source": {"vulnerability": {"severity": "Critical"}}}] * count}}

    @pytest.mark.asyncio
    @pytest.mark.parametrize("first_fails", [False, True])
    async def test_failure_preserves_observations_and_gap(self, first_fails):
        results = {"001": RuntimeError() if first_fails else self.hits(2),
                   "002": self.hits(2) if first_fails else RuntimeError()}
        client, data = await self.dashboard(["001", "002"], results, total=2)
        coverage = data["vulnerability_coverage"]
        assert coverage["status"] == "partial" and coverage["completed_agents"] == 1
        assert coverage["observed_counts"]["critical"] == 2
        assert data["vulnerability_summary"] is None and data["overall_weighted_score"] is None
        assert data["domain_summary"]["A.8"]["weighted_score"] is None
        assert "Known failure" in data["endpoint_device_panel"]["board_summary"]
        gap = next(g for g in (await client.get_iso27001_gap_analysis())["data"]["gaps"] if g["control_id"] == "A.8.8")
        assert gap["gap_type"] == "incomplete_evidence" and gap["score_upper_bound"] == 70
        assert gap["known_failure"]

    @pytest.mark.asyncio
    async def test_truncated_critical_page_and_explicit_agent(self):
        client, data = await self.dashboard(["001"], {"001": self.hits(500, 600)}, total=1, agent_id="001")
        assert data["vulnerability_coverage"]["observed_counts"]["critical"] == 500
        assert data["vulnerability_coverage"]["reasons"] == ["page_truncated"]
        assert data["posture"] == "insufficient_data"
        gap = next(g for g in (await client.get_iso27001_gap_analysis("001"))["data"]["gaps"] if g["control_id"] == "A.8.8")
        assert gap["severity"] == "critical" and gap["score_upper_bound"] == 0

    @pytest.mark.asyncio
    async def test_zero_and_incomplete_targets(self):
        _, empty = await self.dashboard([], {}, total=0)
        assert empty["vulnerability_coverage"]["status"] == "unavailable"
        _, incomplete = await self.dashboard(["001"], {"001": self.hits(0)}, total=2)
        assert incomplete["vulnerability_coverage"]["status"] == "partial"
        assert "target_list_incomplete" in incomplete["vulnerability_coverage"]["reasons"]
        _, explicit = await self.dashboard(["001"], {"001": self.hits(0)}, total=1, agent_id="001")
        assert explicit["vulnerability_coverage"]["status"] == "complete"
        assert explicit["vulnerability_summary"]["critical"] == 0
        assert next(c for c in explicit["controls"] if c["control_id"] == "A.8.8")["score"] == 100

    @pytest.mark.asyncio
    @pytest.mark.parametrize("total", [None, "1", {"value": 1, "relation": "gte"}, -1])
    async def test_unknown_manager_total(self, total):
        _, data = await self.dashboard(["001"], {"001": self.hits(0)}, total=total)
        assert data["vulnerability_coverage"]["status"] == "partial"
        assert data["vulnerability_coverage"]["expected_agents"] is None
        assert "unknown_total" in data["vulnerability_coverage"]["reasons"]

    @pytest.mark.asyncio
    async def test_budget_and_caller_cancellation(self, monkeypatch):
        import asyncio

        import wazuh_mcp.api.wazuh_client as module

        client = TestISO27001Scoring()._client_with_indexer()
        async def request(method, endpoint, **kwargs):
            if endpoint == "/agents":
                return {"data": {"affected_items": [{"id": "001"}], "total_affected_items": 1,
                                 "total_failed_items": 0}}
            return {"data": {"affected_items": []}}
        async def alerts(**kwargs):
            return {"data": {"affected_items": []}}
        started = asyncio.Event()
        async def slow(**kwargs):
            started.set()
            await asyncio.Event().wait()
        client._request = request
        client.get_alerts = alerts
        client._indexer_client.get_vulnerabilities = slow
        real_timeout = asyncio.timeout
        monkeypatch.setattr(module.asyncio, "timeout", lambda _: real_timeout(0.01))
        data = (await client.get_iso27001_dashboard())["data"]
        assert data["vulnerability_coverage"]["status"] == "unavailable"
        assert "source_unavailable" in data["vulnerability_coverage"]["reasons"]
        started.clear()
        task = asyncio.create_task(client.get_iso27001_dashboard())
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    @pytest.mark.asyncio
    async def test_unrecognized_severity_is_incomplete(self):
        response = {"hits": {"total": 1, "hits": [{"_source": {"vulnerability": {"severity": 123}}}]}}
        _, data = await self.dashboard(["001"], {"001": response}, total=1)
        assert data["vulnerability_coverage"]["status"] == "partial"
        assert "unknown_severity" in data["vulnerability_coverage"]["reasons"]
        assert data["overall_weighted_score"] is None
