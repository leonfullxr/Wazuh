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
        "codex_path": SELECTED,
        "auth_path": "/synthetic/auth",
        "bwrap_path": "/synthetic/bwrap",
        "authority_path": str(worker.host_authority_path()),
        **changes,
    }
    path = tmp_path / "model.json"
    path.write_text(json.dumps(data))
    return path


def test_configuration_defaults_and_fixed_pins(tmp_path):
    default = worker.load_config(config_file(tmp_path)).codex_profile()
    selected = worker.load_config(
        config_file(tmp_path, codex_path="/another/codex")
    ).codex_profile()
    assert default.codex_path == SELECTED
    assert selected.codex_path == "/another/codex"
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


def test_legacy_authority_is_explicit_and_keeps_canonical_row(tmp_path, monkeypatch):
    from dataclasses import replace

    slot = tmp_path / "slot"
    slot.mkdir(mode=0o700)
    alias = tmp_path / "alias"
    alias.symlink_to(slot, target_is_directory=True)
    parent = tmp_path / "parent"
    parent.mkdir(mode=0o700)
    parent_alias = tmp_path / "parent-alias"
    parent_alias.symlink_to(parent, target_is_directory=True)
    authority = parent_alias / "authority"
    monkeypatch.setattr(worker, "host_authority_path", lambda: authority)
    config = worker.ModelConfig(
        frozenset({"site"}),
        worker.local_host_id(),
        "runtime",
        slot,
        codex_path="/fixture/codex",
        auth_path="/fixture/auth",
        bwrap_path="/fixture/bwrap",
        authority_path=authority,
        authority_slot_directory=alias,
    )
    loaded = worker.load_config(config_file(tmp_path, authority_slot_directory=str(alias)))
    assert loaded.authority_slot_directory == alias
    info = worker.protected_directory(slot)
    material = worker.authority_material(config, info)
    authority.write_bytes(material)
    authority.chmod(0o600)
    row = (config.host_id, config.runtime_id, str(slot), info.st_dev, info.st_ino, 1)
    conn = SimpleNamespace(execute=lambda *_: SimpleNamespace(fetchone=lambda: row))
    worker.verify_binding(conn, config, "site")
    with pytest.raises(PermissionError, match="host_runtime_already_bound"):
        worker.verify_binding(conn, replace(config, authority_slot_directory=None), "site")
    conn = SimpleNamespace(
        execute=lambda *_: SimpleNamespace(fetchone=lambda: (*row[:2], str(alias), *row[3:]))
    )
    with pytest.raises(PermissionError, match="runtime_binding_not_provisioned_or_changed"):
        worker.verify_binding(conn, config, "site")
    authority.write_bytes(
        worker.authority_material(replace(config, authority_slot_directory=None), info)
    )
    with pytest.raises(PermissionError, match="host_runtime_already_bound"):
        worker.verify_authority(config, info)
    authority.write_bytes(material)
    target = authority.with_name("target")
    authority.rename(target)
    authority.symlink_to(target)
    with pytest.raises(OSError):
        worker.verify_authority(config, info)
    authority.unlink()
    target.rename(authority)
    with pytest.raises(FileNotFoundError):
        worker.run_model_once(
            conn, config=config, config_path=tmp_path / "unopened-config", wait=False
        )
    assert not (slot / "slot-0.lock").exists()
    other_parent = tmp_path / "other-parent"
    other_parent.mkdir(mode=0o700)
    other_authority = other_parent / authority.name
    other_authority.write_bytes(material)
    other_authority.chmod(0o600)
    original_open = worker.os.open

    def retarget_after_open(path, *args, **kwargs):
        fd = original_open(path, *args, **kwargs)
        if path == authority:
            parent_alias.unlink()
            parent_alias.symlink_to(other_parent, target_is_directory=True)
        return fd

    with monkeypatch.context() as patch:
        patch.setattr(worker.os, "open", retarget_after_open)
        with pytest.raises(PermissionError, match="host_authority_changed"):
            worker.verify_authority(config, info)
    parent_alias.unlink()
    parent_alias.symlink_to(parent, target_is_directory=True)
    other = tmp_path / "other"
    other.mkdir(mode=0o700)
    alias.unlink()
    alias.symlink_to(other, target_is_directory=True)
    with pytest.raises(PermissionError, match="authority_slot_directory_changed"):
        worker.verify_authority(config, info)
    assert authority.read_bytes() == material


def test_alias_provision_cannot_create_slot_or_authority(tmp_path, monkeypatch):
    from dataclasses import replace

    slot = tmp_path / "slot"
    alias = tmp_path / "alias"
    authority = tmp_path / "authority"
    monkeypatch.setattr(worker, "host_authority_path", lambda: authority)
    config = worker.ModelConfig(
        frozenset({"site"}),
        worker.local_host_id(),
        "runtime",
        slot,
        codex_path="/fixture/codex",
        auth_path="/fixture/auth",
        bwrap_path="/fixture/bwrap",
        authority_path=authority,
        authority_slot_directory=alias,
    )
    with pytest.raises(FileNotFoundError):
        worker.provision_binding(object(), config, now=datetime.now(UTC))
    assert not slot.exists()
    slot.mkdir(mode=0o700)
    alias.symlink_to(slot, target_is_directory=True)
    with pytest.raises(FileNotFoundError):
        worker.provision_binding(object(), config, now=datetime.now(UTC))
    assert not authority.exists()
    with pytest.raises(ValueError):
        replace(config, authority_slot_directory=slot)
    with pytest.raises(ValueError):
        worker.load_config(config_file(tmp_path, authority_slot_directory="/a/../b"))
