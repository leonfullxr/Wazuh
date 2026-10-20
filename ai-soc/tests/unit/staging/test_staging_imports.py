from __future__ import annotations

import importlib
import pkgutil

import ai_soc.qualification
import scripts.staging


def test_every_staging_and_qualification_module_imports() -> None:
    # Pyright intentionally covers only contracts/config, and unit collection
    # previously did not import every CLI/reload module. Keep runtime import
    # resolution covered, including imports reached only by resumed sessions.
    packages = (scripts.staging, ai_soc.qualification)
    modules = sorted(
        module.name
        for package in packages
        for module in pkgutil.walk_packages(package.__path__, package.__name__ + ".")
    )

    assert modules
    for module_name in modules:
        importlib.import_module(module_name)
