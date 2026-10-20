from __future__ import annotations

import builtins
import importlib


def test_packaged_probe_modules_import_without_staging_scripts(monkeypatch) -> None:
    original_import = builtins.__import__

    def reject_staging(name, *args, **kwargs):
        if name == "scripts" or name.startswith("scripts."):
            raise AssertionError(f"task wheel imported staging module {name}")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", reject_staging)
    importlib.import_module("ai_soc.qualification.mcp_models")
    importlib.import_module("ai_soc.qualification.mcp_oauth")
    importlib.import_module("ai_soc.qualification.mcp_protocol")
    importlib.import_module("ai_soc.qualification.mcp_task")
    importlib.import_module("ai_soc.qualification.mcp_probe")
    importlib.import_module("ai_soc.qualification.state_probe")
