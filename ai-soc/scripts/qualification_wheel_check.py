from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build" / "qualification-wheel-check"
WHEELS = BUILD / "wheels"
INSTALL = BUILD / "installed"


def main() -> int:
    shutil.rmtree(BUILD, ignore_errors=True)
    WHEELS.mkdir(parents=True)
    subprocess.run(
        ["uv", "build", "--offline", "--wheel", "--out-dir", str(WHEELS)],
        cwd=ROOT,
        check=True,
    )
    wheel_paths = tuple(WHEELS.glob("*.whl"))
    if len(wheel_paths) != 1:
        raise RuntimeError("qualification wheel build did not produce one wheel")
    subprocess.run(
        [
            "uv",
            "pip",
            "install",
            "--offline",
            "--no-deps",
            "--target",
            str(INSTALL),
            str(wheel_paths[0]),
        ],
        cwd=ROOT,
        check=True,
    )
    code = f"""
import builtins
import importlib
import pathlib
import sys

install = pathlib.Path({str(INSTALL)!r}).resolve()
root = pathlib.Path({str(ROOT)!r}).resolve()
sys.path = [entry for entry in sys.path if pathlib.Path(entry or '.').resolve() != root]
sys.path.insert(0, str(install))
original_import = builtins.__import__
def checked_import(name, *args, **kwargs):
    if name == 'scripts' or name.startswith('scripts.'):
        raise AssertionError(f'wheel task imported {{name}}')
    return original_import(name, *args, **kwargs)
builtins.__import__ = checked_import
for module in (
    'ai_soc.qualification.mcp_models',
    'ai_soc.qualification.mcp_oauth',
    'ai_soc.qualification.mcp_protocol',
    'ai_soc.qualification.mcp_task',
    'ai_soc.qualification.mcp_probe',
    'ai_soc.qualification.state_probe',
):
    imported = importlib.import_module(module)
    if not pathlib.Path(imported.__file__).resolve().is_relative_to(install):
        raise AssertionError(f'{{module}} did not load from the installed wheel')
"""
    subprocess.run(
        [sys.executable, "-I", "-c", code],
        cwd=BUILD,
        check=True,
    )
    print("qualification wheel task imports passed without scripts/ on sys.path")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
