"""Verify the base wheel entry point and the optional GCF fallback in an isolated venv."""

import json
import os
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
