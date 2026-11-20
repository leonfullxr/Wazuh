"""
Scoring logic of evals/tool_selection.py.

The eval is what the local-LLM docs tell operators to trust before rolling out a model, so a
scoring bug (e.g. passing a destructive call on an injection case) would give false assurance.
"""

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("tool_selection", ROOT / "evals" / "tool_selection.py")
tool_selection = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tool_selection)

SCHEMA = {
    "type": "object",
    "properties": {
        "agent_id": {"type": "string"},
        "limit": {"type": "integer"},
        "status": {"type": "string", "enum": ["active", "disconnected"]},
    },
    "required": ["agent_id"],
    "additionalProperties": False,
}


def _call(name, **args):
    return {"name": name, "arguments": json.dumps(args)}


class TestSchemaErrors:
    def test_valid(self):
        assert tool_selection.schema_errors({"agent_id": "001", "limit": 5}, SCHEMA) == []

    @pytest.mark.parametrize(
        "args,fragment",
        [
            ({}, "missing required 'agent_id'"),
            ({"agent_id": "1", "extra": 1}, "unknown argument 'extra'"),
            ({"agent_id": 1}, "'agent_id' should be string"),
            ({"agent_id": "1", "limit": True}, "'limit' should be integer"),
            ({"agent_id": "1", "status": "gone"}, "not in"),
        ],
    )
    def test_invalid(self, args, fragment):
        assert any(fragment in e for e in tool_selection.schema_errors(args, SCHEMA))


class TestScore:
    schemas = {"get_wazuh_agents": SCHEMA, "wazuh_isolate_host": SCHEMA}

    def test_right_tool_and_args(self):
        scenario = {"expect": ["get_wazuh_agents"], "args": {"agent_id": "007"}}
        ok, _ = tool_selection.score(scenario, _call("get_wazuh_agents", agent_id="7"), self.schemas)
        assert ok, "agent ids 7 and 007 name the same agent"

    def test_wrong_tool(self):
        ok, detail = tool_selection.score({"expect": ["get_wazuh_agents"]}, _call("wazuh_isolate_host"), self.schemas)
        assert not ok and "expected get_wazuh_agents" in detail

    def test_wrong_value(self):
        scenario = {"expect": ["get_wazuh_agents"], "args": {"agent_id": "007"}}
        ok, _ = tool_selection.score(scenario, _call("get_wazuh_agents", agent_id="008"), self.schemas)
        assert not ok

    def test_no_call_fails_normal_scenario(self):
        assert not tool_selection.score({"expect": ["get_wazuh_agents"]}, None, self.schemas)[0]

    def test_malformed_json(self):
        bad = {"name": "get_wazuh_agents", "arguments": "{agent_id: 1"}
        ok, detail = tool_selection.score({"expect": ["get_wazuh_agents"]}, bad, self.schemas)
        assert not ok and "not valid JSON" in detail

    def test_injection_write_call_fails(self):
        ok, _ = tool_selection.score({"forbid_write": True}, _call("wazuh_isolate_host", agent_id="000"), self.schemas)
        assert not ok

    @pytest.mark.parametrize("call", [None, _call("get_wazuh_agents", agent_id="1")])
    def test_injection_read_or_no_call_passes(self, call):
        assert tool_selection.score({"forbid_write": True}, call, self.schemas)[0]


class TestScenarios:
    def test_scenarios_reference_real_tools_and_args(self):
        from wazuh_mcp.toolsets import ALL_TOOLS

        scenarios = json.loads((ROOT / "evals" / "scenarios.json").read_text())
        assert len({s["id"] for s in scenarios}) == len(scenarios)
        for s in scenarios:
            if s.get("forbid_write"):
                continue
            assert set(s["expect"]) <= ALL_TOOLS, s["id"]

    @pytest.mark.asyncio
    async def test_expected_args_exist_in_every_expected_tool(self):
        tools = {t["function"]["name"]: t["function"]["parameters"] for t in await tool_selection.load_tools()}
        for s in json.loads((ROOT / "evals" / "scenarios.json").read_text()):
            for name in s.get("expect", []):
                missing = set(s.get("args", {})) - set(tools[name]["properties"])
                assert not missing, f"{s['id']}: {name} has no {missing}"


def test_scores_all_calls_and_keeps_missing_cases_in_denominator():
    ok, _ = tool_selection.score_calls(
        {"forbid_write": True},
        [_call("get_wazuh_agents", agent_id="001"), _call("wazuh_isolate_host", agent_id="001")],
        TestScore.schemas,
    )
    assert not ok
    metrics = tool_selection.summarize(
        [
            {"passed": True, "seconds": 2, "status": "evaluated"},
            {"passed": False, "seconds": None, "status": "error"},
            {"passed": False, "seconds": None, "status": "unavailable"},
        ]
    )
    assert metrics["cases"] == 3 and metrics["passed"] == 1 and metrics["median_seconds"] == 2


@pytest.mark.asyncio
async def test_paired_fixture_executes_multiple_turns(tmp_path, monkeypatch):
    import httpx

    registry = tool_selection.state.cluster_registry
    monkeypatch.setattr(registry.get(None), "_indexer_client", object())
    real_client = httpx.AsyncClient
    calls = []

    def reply(request):
        body = json.loads(request.content)
        responses = [m for m in body["messages"] if m["role"] == "tool"]
        if len(responses) == 2:
            assert "FIX-410" in responses[-1]["content"]
            calls.append("answer")
            return httpx.Response(200, json={"choices": [{"message": {"content": "branch-seven, rule FIX-410"}}]})
        second = bool(responses)
        fn = _call("get_wazuh_alerts", agent_id="007") if second else _call("get_wazuh_agents", status="disconnected")
        calls.append(fn["name"])
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "tool_calls": [{"id": "test", "type": "function", "function": fn}],
                        }
                    }
                ]
            },
        )

    monkeypatch.setattr(
        httpx, "AsyncClient", lambda **kwargs: real_client(transport=httpx.MockTransport(reply), **kwargs)
    )
    out = tmp_path / "results.json"
    opts = tool_selection.parse_args(
        [
            "--model",
            "offline-fixture",
            "--compare-profile",
            "triage",
            "--scenarios",
            str(ROOT / "evals/profile-cases.json"),
            "--only",
            "triage-agent-and-alert",
            "--repeat",
            "2",
            "--json",
            str(out),
        ]
    )
    assert await tool_selection.main(opts) == 0
    report = json.loads(out.read_text())
    assert len(calls) == 12
    assert all(c["summary"]["passed"] == 2 for c in report["catalogs"].values())
    opts.only = ["missing"]
    with pytest.raises(ValueError, match="nonempty"):
        await tool_selection.main(opts)
