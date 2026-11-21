"""Check the MCP read contracts against pinned projections of official Wazuh releases."""

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# Path parameters are provided by the adapters. No read endpoint needs an extra required query.
READS = {
    "/": (None, "validate_wazuh_connection"),
    "/agents": ("agent:read", "get_wazuh_agents, get_iso27001_dashboard, investigate_agent_timeline"),
    "/groups/{group_id}/configuration": ("group:read", "get_agent_configuration"),
    "/syscollector/{agent_id}/processes": ("syscollector:read", "get_agent_processes, wazuh_check_process"),
    "/syscollector/{agent_id}/ports": ("syscollector:read", "get_agent_ports"),
    "/syscheck/{agent_id}": ("syscheck:read", "wazuh_check_file_quarantine"),
    "/sca/{agent_id}": ("sca:read", "run_compliance_check, get_iso27001_dashboard"),
    "/sca/{agent_id}/checks/{policy_id}": ("sca:read", "get_sca_policy_checks"),
    "/rules": ("rules:read", "get_wazuh_rules_summary"),
    "/manager/logs": ("manager:read", "search_wazuh_manager_logs, get_wazuh_manager_error_logs"),
    "/manager/stats": ("manager:read", "get_wazuh_statistics"),
    "/manager/stats/weekly": ("manager:read", "get_wazuh_weekly_stats"),
    "/manager/stats/analysisd": ("manager:read", "get_wazuh_analysisd_stats, get_wazuh_log_collector_stats, get_iso27001_dashboard"),
    "/manager/stats/remoted": ("manager:read", "get_wazuh_remoted_stats"),
    "/cluster/healthcheck": ("cluster:read", "get_wazuh_cluster_health"),
    "/cluster/nodes": ("cluster:read", "get_wazuh_cluster_nodes"),
}
FIELDS = {"agent.id": "keyword", "vulnerability.id": "keyword", "vulnerability.severity": "keyword"}
TIMELINE_AGENT_PARAMS = {"agents_list", "select"}
VULN_TOOLS = "get_wazuh_vulnerabilities, get_wazuh_critical_vulnerabilities, get_iso27001_dashboard"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def project(spec_path, mapping_path):
    """Extract factual metadata only. PyYAML is required just for regenerating snapshots."""
    import yaml

    spec = yaml.safe_load(spec_path.read_bytes())
    mappings = json.loads(mapping_path.read_bytes())["template"]["mappings"]["properties"]
    ops = {}
    for path in READS:
        item = spec["paths"].get(path, {})
        op = item.get("get")
        if op is None:
            continue
        required = []
        query_params = set()
        for param in item.get("parameters", []) + op.get("parameters", []):
            if "$ref" in param:
                param = spec["components"]["parameters"][param["$ref"].split("/")[-1]]
            if param.get("required"):
                required.append([param["in"], param["name"]])
            if param["in"] == "query":
                query_params.add(param["name"])
        ops[path] = {
            "required": sorted(required),
            "actions": sorted(x["$ref"].split("/")[-1] for x in op.get("x-rbac-actions", [])),
            "deprecated": op.get("deprecated", False),
        }
        if path == "/agents":
            ops[path]["timeline_query_params"] = sorted(TIMELINE_AGENT_PARAMS & query_params)
    fields = {}
    for field in FIELDS:
        group, key = field.split(".")
        fields[field] = mappings.get(group, {}).get("properties", {}).get(key, {}).get("type")
    return {"manager": ops, "fields": fields}


def compare(snapshot):
    errors = []
    warnings = []
    for path, (action, tools) in READS.items():
        op = snapshot["manager"].get(path)
        required = sorted(["path", part[1:-1]] for part in path.split("/") if part.startswith("{"))
        if op is None:
            errors.append(f"Missing GET {path} affects {tools}")
            continue
        if op["required"] != required or op["actions"] != ([action] if action else []):
            errors.append(f"GET {path} changed required parameters or RBAC, affecting {tools}")
        if path == "/agents":
            missing = TIMELINE_AGENT_PARAMS.difference(op.get("timeline_query_params", []))
            if missing:
                errors.append(f"GET /agents lacks {', '.join(sorted(missing))} for investigate_agent_timeline")
        if op["deprecated"]:
            warnings.append(f"GET {path} deprecated for {tools}. Check /manager/daemons/stats as a replacement.")
    for field, expected in FIELDS.items():
        if snapshot["fields"].get(field) != expected:
            errors.append(f"Indexer field {field} requires {expected} for {VULN_TOOLS}")
    return errors, warnings


def verify():
    manifest = json.loads((ROOT / "manifest.json").read_text())
    ok = True
    for version, entry in manifest.items():
        path = ROOT / "snapshots" / f"{version}.json"
        if digest(path) != entry["snapshot_sha256"]:
            print(f"{version}: snapshot hash mismatch")
            ok = False
            continue
        errors, warnings = compare(json.loads(path.read_bytes()))
        print(f"{version}: {len(errors)} errors, {len(warnings)} deprecations")
        for message in [*errors, *warnings]:
            print(f"  {message}")
        ok = ok and not errors
    return ok


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", nargs=2, type=Path, metavar=("MANAGER_SPEC", "INDEXER_TEMPLATE"))
    args = parser.parse_args()
    if args.project:
        print(json.dumps(project(*args.project), indent=2, sort_keys=True))
    else:
        raise SystemExit(0 if verify() else 1)
