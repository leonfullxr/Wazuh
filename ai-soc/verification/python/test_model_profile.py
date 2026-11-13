"""Synthetic model-profile propagation checks; no account or provider access."""

import json
import subprocess
import sys
from contextlib import nullcontext
from dataclasses import fields
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import UUID

import pytest

from ai_soc.workspace.model import guardian, worker
from ai_soc.workspace.model.bundle import freeze_execution, supported_execution
from ai_soc.workspace.model.cli_profile import CodexProfile

SELECTED = "/synthetic/bin/codex"


@pytest.fixture(autouse=True)
def no_account_access(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("account access forbidden")

    monkeypatch.setattr(CodexProfile, "verify", forbidden)
    monkeypatch.setattr("ai_soc.workspace.model.cli_credentials.load_credentials", forbidden)


def config_file(tmp_path, **changes):
    data = {
        "site_ids": ["synthetic"],
        "host_id": "host",
        "runtime_id": "runtime",
        "slot_directory": str(tmp_path),
        **changes,
    }
    path = tmp_path / "model.json"
    path.write_text(json.dumps(data))
    return path


def test_configuration_defaults_and_fixed_pins(tmp_path):
    default = worker.load_config(config_file(tmp_path)).codex_profile()
    selected = worker.load_config(config_file(tmp_path, codex_path=SELECTED)).codex_profile()
    assert default == CodexProfile()
    assert selected.codex_path == SELECTED
    for field in fields(CodexProfile):
        if field.name != "codex_path":
            assert getattr(selected, field.name) == getattr(default, field.name)
    assert selected.codex_version == "codex-cli 0.164.0"
    assert (
        selected.codex_sha256 == "b93f6811d3f653f0fb83be4050d857fb9abbb111dfa2ce160563327daff7f306"
    )


@pytest.mark.parametrize("value", [None, True, 1, [], {}, "", "relative/codex", "/bad\x00path"])
def test_invalid_path_fails_safely(tmp_path, value):
    with pytest.raises(ValueError, match="^invalid_model_configuration$"):
        worker.load_config(config_file(tmp_path, codex_path=value))


def test_unknown_field_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="^unknown_model_configuration_field$"):
        worker.load_config(config_file(tmp_path, extra="ignored"))


def test_preparation_main_uses_configured_profile(tmp_path, monkeypatch):
    path = config_file(tmp_path, codex_path=SELECTED)
    observed = []
    monkeypatch.setattr(sys, "argv", ["worker", "prepare", "--config", str(path)])
    monkeypatch.setenv("WS_MODEL_DATABASE_URL", "synthetic")
    monkeypatch.setattr(worker.psycopg, "connect", lambda *_: nullcontext(object()))

    def run_once(_conn, **kwargs):
        observed.append(kwargs["handler"].profile)
        return 0

    monkeypatch.setattr(worker, "run_once", run_once)
    assert worker.main() == 0
    assert [profile.codex_path for profile in observed] == [SELECTED]


def test_status_selects_profile_and_preserves_explicit_injection(tmp_path, monkeypatch):
    config = worker.load_config(config_file(tmp_path, codex_path=SELECTED))
    observed = []
    monkeypatch.setattr(
        CodexProfile, "verify_runtime", lambda self: observed.append(self.codex_path)
    )
    monkeypatch.setattr(worker, "site_transaction", lambda *_: nullcontext())
    monkeypatch.setattr(worker, "verify_binding", lambda *_: None)
    monkeypatch.setattr(worker, "acquire_slot", lambda *_: None)
    conn = SimpleNamespace(execute=lambda *_: SimpleNamespace(fetchall=lambda: []))
    worker.model_status(conn, config)
    worker.model_status(conn, config, CodexProfile(codex_path="/injected/codex"))
    assert observed == [SELECTED, "/injected/codex"]


def test_path_changes_identity_and_unsupported_job_is_not_claimed(tmp_path, monkeypatch):
    config = worker.load_config(config_file(tmp_path, codex_path=SELECTED))
    chosen = config.codex_profile()
    other = CodexProfile(codex_path="/other/codex")
    pack = SimpleNamespace(canonical_bytes=lambda: b"{}")
    frozen = freeze_execution(pack, other)
    selected = freeze_execution(pack, chosen)
    snapshot = frozen.digest("a" * 64)
    assert snapshot != selected.digest("a" * 64)
    assert supported_execution(frozen, other)
    assert not supported_execution(frozen, chosen)
    job_id = UUID(int=1)
    row = (1, "synthetic", "narrate", "subject", {"generation_id": str(job_id)}, 0)
    statements = []

    class Connection:
        def execute(self, sql, _params):
            statements.append(sql)
            return SimpleNamespace(fetchall=lambda: [row])

    monkeypatch.setattr(
        guardian, "load_generation", lambda *_, **__: SimpleNamespace(execution=frozen)
    )
    assert (
        guardian._claim_supported(Connection(), config, "synthetic", chosen, datetime.now(UTC))
        is None
    )
    assert len(statements) == 1
    assert frozen.digest("a" * 64) == snapshot


def test_separate_guardian_loads_configured_profile(tmp_path, monkeypatch):
    path = config_file(tmp_path, codex_path=SELECTED)
    config = worker.load_config(path)
    slot = worker.acquire_slot(tmp_path)
    assert slot is not None
    original_popen = subprocess.Popen
    child_code = """
import sys
from contextlib import nullcontext
from types import SimpleNamespace
from ai_soc.workspace.model import guardian
from ai_soc.workspace.model.cli_profile import CodexProfile, ProfileError

def verify(profile):
    print(profile.codex_path, flush=True)
    raise ProfileError("synthetic_unavailable")

CodexProfile.verify_runtime = verify
CodexProfile.verify = lambda *a: (_ for _ in ()).throw(AssertionError("account access forbidden"))
guardian._short_transaction = lambda *args: nullcontext()
guardian.verify_binding = lambda *args: None
guardian.recover_abandoned_calls = lambda *args, **kwargs: None
def forbidden(*args, **kwargs):
    raise AssertionError("provider called")
guardian.CodexCLIProvider = lambda profile: SimpleNamespace(generate=forbidden)
conn = SimpleNamespace(execute=lambda *a: SimpleNamespace(fetchone=lambda: None))
guardian.psycopg.connect = lambda *args, **kwargs: nullcontext(conn)
sys.argv = ["guardian", "--config", sys.argv[1], "--slot-fd", sys.argv[2]]
raise SystemExit(guardian.main())
"""
    seen = {}

    def spawn(args, **kwargs):
        seen.update(kwargs)
        assert args[2:5] == ["ai_soc.workspace.model.guardian", "--config", str(path)]
        child = original_popen(
            [sys.executable, "-c", child_code, str(path), str(slot.fd)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            **kwargs,
        )
        seen["child"] = child
        return child

    monkeypatch.setattr(worker, "acquire_slot", lambda *_: slot)
    monkeypatch.setattr(worker, "site_transaction", lambda *_: nullcontext())
    monkeypatch.setattr(worker, "verify_binding", lambda *_: None)
    monkeypatch.setattr(worker.subprocess, "Popen", spawn)
    conn = SimpleNamespace(info=SimpleNamespace(dsn="synthetic"))
    assert (
        worker.run_model_once(conn, config=config, config_path=path, dsn="synthetic", wait=False)
        == 1
    )
    child = seen["child"]
    stdout, stderr = child.communicate(timeout=15)
    assert child.returncode == 3, stderr.decode(errors="replace")
    assert stdout.decode().strip() == SELECTED
    assert seen["pass_fds"] and seen["close_fds"] and seen["start_new_session"]
    assert set(seen["env"]) == {"PATH", "LANG", "PYTHONPATH", "WS_MODEL_DATABASE_URL"}
