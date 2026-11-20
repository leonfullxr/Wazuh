"""Verify the base wheel entry point and the optional GCF fallback in an isolated venv."""

import json
import os
import subprocess
from importlib import metadata, util
from pathlib import Path
from sys import prefix

os.environ.update(AUTH_MODE="none", ENVIRONMENT="development", RESPONSE_FORMAT="gcf")
from wazuh_mcp.gcf_format import render_result  # noqa: E402

if util.find_spec("gcf") is not None:
    raise RuntimeError("The smoke environment must contain only the base wheel and its dependencies")
entry = next(ep for ep in metadata.distribution("wazuh-mcp").entry_points if ep.name == "wazuh-mcp")
assert callable(entry.load())
assert (Path(prefix) / "bin" / entry.name).is_file()
assert json.loads(render_result("sample", {"ok": True}, compact=True).split("\n", 1)[1]) == {"ok": True}

preflight = next(ep for ep in metadata.distribution("wazuh-mcp").entry_points if ep.name == "wazuh-mcp-preflight")
assert callable(preflight.load())
preflight_path = Path(prefix) / "bin" / preflight.name
assert preflight_path.is_file()
help_output = subprocess.run([str(preflight_path), "--help"], check=True, capture_output=True, text=True)
assert "--tie-breaker" in help_output.stdout
