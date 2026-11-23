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
guardian.verify_binding = lambda *args, **kwargs: None
guardian.recover_abandoned_calls = lambda *args, **kwargs: None
def forbidden(*args, **kwargs):
    raise AssertionError("provider called")
guardian.CodexCLIProvider = lambda profile: SimpleNamespace(generate=forbidden)
conn = SimpleNamespace(execute=lambda *a: SimpleNamespace(fetchone=lambda: None))
guardian.psycopg.connect = lambda *args, **kwargs: nullcontext(conn)
sys.argv = ["guardian", "--config", sys.argv[1], "--slot-fd", sys.argv[2],
            "--legacy-slot-fd", sys.argv[3]]
raise SystemExit(guardian.main())
"""
    seen = {}

    def spawn(args, **kwargs):
        seen.update(kwargs)
        assert args[2:5] == ["ai_soc.workspace.model.guardian", "--config", str(path)]
        assert args[-4:] == ["--slot-fd", str(slot.fd), "--legacy-slot-fd", str(slot.legacy_fd)]
        assert kwargs["pass_fds"] == (slot.fd, slot.legacy_fd)
        child = original_popen(
            [sys.executable, "-c", child_code, str(path), str(slot.fd), str(slot.legacy_fd)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            **kwargs,
        )
        seen["child"] = child
        return child

    monkeypatch.setattr(worker, "acquire_slot", lambda *_: slot)
    monkeypatch.setattr(worker, "site_transaction", lambda *_: nullcontext())
    monkeypatch.setattr(worker, "verify_binding", lambda *_, **_kwargs: None)
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


def test_directory_lock_survives_replaced_legacy_entry(tmp_path):
    slot = worker.acquire_slot(tmp_path)
    assert slot is not None
    try:
        (tmp_path / "slot-0.lock").unlink()
        code = (
            "from pathlib import Path; from ai_soc.workspace.model.worker import acquire_slot; "
            "import sys; slot=acquire_slot(Path(sys.argv[1])); "
            "sys.exit(0 if slot is None else 1)"
        )
        assert (
            subprocess.run([sys.executable, "-c", code, str(tmp_path)], check=False).returncode == 0
        )
    finally:
        slot.close()
    replacement = worker.acquire_slot(tmp_path)
    assert replacement is not None
    replacement.close()


def test_slot_rejects_hardlinked_legacy_file(tmp_path):
    path = tmp_path / "slot-0.lock"
    path.touch(mode=0o600)
    (tmp_path / "other").hardlink_to(path)
    with pytest.raises(PermissionError, match="slot_file_changed"):
        worker.acquire_slot(tmp_path)


def test_alias_enrollment_requires_existing_lock_before_sql(tmp_path, monkeypatch):
    slot = tmp_path / "slot"
    slot.mkdir(mode=0o700)
    alias = tmp_path / "alias"
    alias.symlink_to(slot)
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
    authority.write_bytes(worker.authority_material(config, slot.stat()))
    authority.chmod(0o600)
    monkeypatch.setattr(worker, "site_transaction", lambda *_: nullcontext())

    class Database:
        def execute(self, query, *args):
            if query.startswith("SELECT"):
                return SimpleNamespace(fetchone=lambda: None)
            raise AssertionError("enrollment reached INSERT before validating the lock")

    with pytest.raises(FileNotFoundError):
        worker.provision_binding(Database(), config, now=datetime.now(UTC))
    assert not (slot / "slot-0.lock").exists()


def test_slot_refuses_replaced_entry_after_lock(tmp_path, monkeypatch):
    import fcntl

    original = worker.fcntl.flock

    def replace_entry(fd, operation):
        result = original(fd, operation)
        if not (operation & fcntl.LOCK_UN) and worker.stat.S_ISREG(worker.os.fstat(fd).st_mode):
            path = tmp_path / "slot-0.lock"
            path.rename(tmp_path / "original-lock")
            path.touch(mode=0o600)
        return result

    monkeypatch.setattr(worker.fcntl, "flock", replace_entry)
    with pytest.raises(PermissionError, match="slot_file_changed"):
        worker.acquire_slot(tmp_path)
    monkeypatch.setattr(worker.fcntl, "flock", original)
    slot = worker.acquire_slot(tmp_path)
    assert slot is not None
    slot.close()


def test_authority_observation_races(tmp_path, monkeypatch):
    slot = tmp_path / "slot"
    slot.mkdir(mode=0o700)
    alias = tmp_path / "alias"
    alias.symlink_to(slot)
    authority = tmp_path / "authority"
    config = worker.ModelConfig(
        frozenset({"site"}),
        "host",
        "runtime",
        slot,
        authority_path=authority,
        authority_slot_directory=alias,
    )
    material = worker.authority_material(config, slot.stat())
    authority.write_bytes(material)
    authority.chmod(0o600)
    original_open = worker.os.open

    def swap_alias(path, *args, **kwargs):
        fd = original_open(path, *args, **kwargs)
        if path == authority:
            alias.unlink()
            alias.symlink_to(slot)
        return fd

    with monkeypatch.context() as patch:
        patch.setattr(worker.os, "open", swap_alias)
        worker.verify_authority(config, slot.stat())

    def replace_manifest(path, *args, **kwargs):
        if path == authority:
            replacement = tmp_path / "replacement"
            replacement.write_bytes(material)
            replacement.chmod(0o600)
            replacement.replace(authority)
        return original_open(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(worker.os, "open", replace_manifest)
        with pytest.raises(PermissionError, match="host_authority_changed"):
            worker.verify_authority(config, slot.stat())


def test_legacy_only_holder_blocks_and_releases_directory(tmp_path):
    path = tmp_path / "slot-0.lock"
    path.touch(mode=0o600)
    code = (
        "import fcntl,sys; f=open(sys.argv[1], 'r+'); "
        "fcntl.flock(f.fileno(),fcntl.LOCK_EX); print('ready',flush=True); sys.stdin.read()"
    )
    process = subprocess.Popen(
        [sys.executable, "-c", code, str(path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert process.stdout is not None and process.stdout.readline().strip() == "ready"
        assert worker.acquire_slot(tmp_path) is None
    finally:
        assert process.stdin is not None
        process.stdin.close()
        assert process.wait(timeout=5) == 0
    slot = worker.acquire_slot(tmp_path)
    assert slot is not None
    slot.close()


def test_slot_rejects_link_added_before_flock(tmp_path, monkeypatch):
    original = worker.fcntl.flock

    def add_link(fd, operation):
        if worker.stat.S_ISREG(worker.os.fstat(fd).st_mode):
            (tmp_path / "other").hardlink_to(tmp_path / "slot-0.lock")
        return original(fd, operation)

    monkeypatch.setattr(worker.fcntl, "flock", add_link)
    with pytest.raises(PermissionError, match="slot_file_changed"):
        worker.acquire_slot(tmp_path)


def test_sandbox_uses_one_directory_sync_fd(tmp_path):
    from ai_soc.workspace.model.cli_profile import CallInputs

    slot = worker.acquire_slot(tmp_path)
    assert slot is not None
    try:
        inputs = CallInputs(tmp_path, tmp_path, tmp_path, tmp_path, tmp_path, "x", "y")
        args = CodexProfile().argv(inputs, slot_fds=(slot.fd,))
        assert args.count("--sync-fd") == 1
        assert args[args.index("--sync-fd") + 1] == str(slot.fd)
        assert str(slot.legacy_fd) not in args
    finally:
        slot.close()


def test_alias_and_canonical_processes_share_directory_lock(tmp_path):
    slot_path = tmp_path / "slot"
    slot_path.mkdir(mode=0o700)
    alias = tmp_path / "alias"
    alias.symlink_to(slot_path)
    slot = worker.acquire_slot(slot_path)
    assert slot is not None
    code = (
        "from pathlib import Path; from ai_soc.workspace.model.worker import "
        "ModelConfig,_acquire_model_slot; import sys; "
        "c=ModelConfig(frozenset({'s'}),'host','runtime',Path(sys.argv[1]),"
        "authority_slot_directory=Path(sys.argv[2])); s=_acquire_model_slot(c); "
        "sys.exit(0 if s is None else 1)"
    )
    try:
        assert (
            subprocess.run([sys.executable, "-c", code, str(slot_path), str(alias)]).returncode == 0
        )
    finally:
        slot.close()
    alias_slot = worker._acquire_model_slot(
        worker.ModelConfig(
            frozenset({"s"}), "host", "runtime", slot_path, authority_slot_directory=alias
        )
    )
    assert alias_slot is not None
    alias_slot.close()


def test_authority_initial_absence_and_observed_alias_disappearance(tmp_path, monkeypatch):
    slot = tmp_path / "slot"
    slot.mkdir(mode=0o700)
    alias = tmp_path / "alias"
    alias.symlink_to(slot)
    authority = tmp_path / "authority"
    config = worker.ModelConfig(
        frozenset({"site"}),
        "host",
        "runtime",
        slot,
        authority_path=authority,
        authority_slot_directory=alias,
    )
    with pytest.raises(FileNotFoundError):
        worker.verify_authority(config, slot.stat())
    authority.write_bytes(worker.authority_material(config, slot.stat()))
    authority.chmod(0o600)
    original = worker.os.open

    def remove_alias(path, *args, **kwargs):
        fd = original(path, *args, **kwargs)
        if path == authority:
            alias.unlink()
        return fd

    with monkeypatch.context() as patch:
        patch.setattr(worker.os, "open", remove_alias)
        with pytest.raises(PermissionError, match="authority_slot_directory_changed"):
            worker.verify_authority(config, slot.stat())
    with pytest.raises(FileNotFoundError):
        worker.verify_authority(config, slot.stat())


@pytest.mark.parametrize("alias", ["/a/./b", "/a//b", "/a/b/", "//a/b", "/a/../b", "/a/\x00b"])
def test_alias_rejects_non_normalized_spelling(tmp_path, alias):
    with pytest.raises(ValueError, match="invalid_model_configuration"):
        worker.load_config(config_file(tmp_path, authority_slot_directory=alias))


def test_scheduler_handoff_holds_slot_until_last_descendant(tmp_path):
    import os
    import select
    import signal

    slot_path = tmp_path / "slot"
    slot_path.mkdir(mode=0o700)
    for name in (
        "guardian-ready",
        "descendant-ready",
        "guardian-stop",
        "descendant-stop",
        "guardian-life",
        "descendant-life",
    ):
        os.mkfifo(tmp_path / name, 0o600)
    pipes = {
        name: os.open(tmp_path / name, os.O_RDWR | os.O_NONBLOCK)
        for name in ("guardian-ready", "descendant-ready", "guardian-stop", "descendant-stop")
    }
    life_pipes = {
        name: os.open(tmp_path / name, os.O_RDONLY | os.O_NONBLOCK)
        for name in ("guardian-life", "descendant-life")
    }
    guardian = tmp_path / "guardian"
    guardian.write_text(
        f"#!{sys.executable}\n"
        + '''import fcntl, os, subprocess, sys
from pathlib import Path
assert sys.argv[1:3] == ["-m", "ai_soc.workspace.model.guardian"]
assert sys.argv[3] == "--config" and sys.argv[5] == "--slot-fd"
assert sys.argv[7] == "--legacy-slot-fd" and len(sys.argv) == 9
root = Path(sys.argv[4]).parent
life = open(root / "guardian-life", "w")
slot_fd, legacy_fd = int(sys.argv[6]), int(sys.argv[8])
slot, legacy = os.fstat(slot_fd), os.fstat(legacy_fd)
fcntl.flock(slot_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
fcntl.flock(legacy_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
assert os.path.samestat(slot, (root / "slot").stat())
assert os.path.samestat(legacy, (root / "slot/slot-0.lock").stat())
code = """import os,sys
from pathlib import Path
root=Path(sys.argv[1]); fd=int(sys.argv[2]); s=os.fstat(fd)
life=open(root/'descendant-life','w')
with open(root/'descendant-ready','w') as out:
    print(f'{os.getpid()}:{s.st_dev}:{s.st_ino}',file=out,flush=True)
with open(root/'descendant-stop','rb',buffering=0) as stop: stop.read(1)
os.close(fd)
"""
subprocess.Popen([sys.executable, "-c", code, str(root), str(slot_fd)],
                 pass_fds=(slot_fd,), stdin=subprocess.DEVNULL,
                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
with open(root / "guardian-ready", "w") as out:
    print(os.getpid(), file=out, flush=True)
with open(root / "guardian-stop", "rb", buffering=0) as stop:
    stop.read(1)
os.close(slot_fd)
os.close(legacy_fd)
'''
    )
    guardian.chmod(0o700)
    scheduler_code = """
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
import sys
from ai_soc.workspace.model import worker
root=Path(sys.argv[1])
config=worker.ModelConfig(frozenset({"site"}), "host", "runtime", root / "slot",
    codex_path="/synthetic/codex", auth_path="/synthetic/auth", bwrap_path="/synthetic/bwrap",
    authority_path=worker.host_authority_path())
worker.site_transaction=lambda *args: nullcontext()
worker.verify_binding=lambda *args, **kwargs: None
worker.sys.executable=str(root / "guardian")
assert worker.run_model_once(SimpleNamespace(info=SimpleNamespace(dsn="synthetic")),
    config=config, config_path=root / "config.json", dsn="synthetic", wait=False) == 1
"""
    scheduler = subprocess.Popen(
        [sys.executable, "-c", scheduler_code, str(tmp_path)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
    )
    pids = []

    def read_message(name):
        assert select.select([pipes[name]], [], [], 10)[0], f"timed out waiting for {name}"
        return os.read(pipes[name], 128).decode().strip()

    def wait_exit(name):
        fd = life_pipes[name]
        assert select.select([fd], [], [], 10)[0], f"{name} did not close"
        assert os.read(fd, 1) == b""

    try:
        assert scheduler.wait(timeout=10) == 0
        guardian_pid = int(read_message("guardian-ready"))
        pids.append(guardian_pid)
        descendant_pid, device, inode = map(int, read_message("descendant-ready").split(":"))
        pids.append(descendant_pid)
        info = slot_path.stat()
        assert (device, inode) == (info.st_dev, info.st_ino)
        assert worker.acquire_slot(slot_path) is None
        os.write(pipes["guardian-stop"], b"x")
        wait_exit("guardian-life")
        pids.remove(guardian_pid)
        assert worker.acquire_slot(slot_path) is None
        os.write(pipes["descendant-stop"], b"x")
        wait_exit("descendant-life")
        pids.remove(descendant_pid)
        slot = worker.acquire_slot(slot_path)
        assert slot is not None
        slot.close()
    finally:
        if scheduler.poll() is None:
            scheduler.kill()
            scheduler.wait(timeout=10)
        for pid in pids:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        for fd in pipes.values():
            os.close(fd)
        for fd in life_pipes.values():
            os.close(fd)


def test_manifest_replaced_by_directory_does_not_leak_fd(tmp_path, monkeypatch):
    import os

    slot = tmp_path / "slot"
    slot.mkdir(mode=0o700)
    authority = tmp_path / "authority"
    config = worker.ModelConfig(
        frozenset({"site"}), "host", "runtime", slot, authority_path=authority
    )
    authority.write_bytes(worker.authority_material(config, slot.stat()))
    authority.chmod(0o600)
    original = worker.os.open

    def replace_before_open(path, *args, **kwargs):
        if path == authority:
            authority.rename(tmp_path / "old-authority")
            authority.mkdir()
        return original(path, *args, **kwargs)

    before = len(os.listdir("/proc/self/fd"))
    with monkeypatch.context() as patch:
        patch.setattr(worker.os, "open", replace_before_open)
        with pytest.raises(PermissionError, match="host_authority_changed"):
            worker.verify_authority(config, slot.stat())
    assert len(os.listdir("/proc/self/fd")) == before


def test_manifest_parent_retarget_with_hardlink_is_detected(tmp_path, monkeypatch):
    from pathlib import Path

    slot = tmp_path / "slot"
    slot.mkdir(mode=0o700)
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    second.mkdir()
    parent = tmp_path / "parent"
    parent.symlink_to(first, target_is_directory=True)
    authority = parent / "authority"
    config = worker.ModelConfig(
        frozenset({"site"}), "host", "runtime", slot, authority_path=authority
    )
    authority.write_bytes(worker.authority_material(config, slot.stat()))
    authority.chmod(0o600)
    (second / "authority").hardlink_to(first / "authority")
    original = Path.lstat

    def retarget_after_lstat(path, *args, **kwargs):
        result = original(path, *args, **kwargs)
        if path == authority:
            parent.unlink()
            parent.symlink_to(second, target_is_directory=True)
        return result

    with monkeypatch.context() as patch:
        patch.setattr(Path, "lstat", retarget_after_lstat)
        with pytest.raises(PermissionError, match="host_authority_changed"):
            worker.verify_authority(config, slot.stat())


def test_alias_disappearing_between_stat_and_resolve_is_changed(tmp_path, monkeypatch):
    from pathlib import Path

    slot = tmp_path / "slot"
    slot.mkdir(mode=0o700)
    alias = tmp_path / "alias"
    alias.symlink_to(slot)
    authority = tmp_path / "authority"
    config = worker.ModelConfig(
        frozenset({"site"}),
        "host",
        "runtime",
        slot,
        authority_path=authority,
        authority_slot_directory=alias,
    )
    authority.write_bytes(worker.authority_material(config, slot.stat()))
    authority.chmod(0o600)
    original = Path.stat

    def remove_after_stat(path, *args, **kwargs):
        result = original(path, *args, **kwargs)
        if path == alias:
            alias.unlink()
        return result

    with monkeypatch.context() as patch:
        patch.setattr(Path, "stat", remove_after_stat)
        with pytest.raises(PermissionError, match="authority_slot_directory_changed"):
            worker.verify_authority(config, slot.stat())


def test_slot_rejects_symlink_legacy_entry(tmp_path):
    import errno

    target = tmp_path / "target"
    target.touch(mode=0o600)
    (tmp_path / "slot-0.lock").symlink_to(target)
    with pytest.raises(OSError) as error:
        worker.acquire_slot(tmp_path, create=False)
    assert error.value.errno == errno.ELOOP


def test_provider_default_broker_transport_inherits_slot_directory(tmp_path, monkeypatch):
    import os

    from ai_soc.workspace.model import cli_broker, cli_provider

    class ProbeComplete(Exception):
        pass

    instances = []

    class CapturingBroker(cli_broker.InferenceBroker):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            instances.append(self)

    slot = worker.acquire_slot(tmp_path)
    assert slot is not None
    executable = tmp_path / "transport"
    executable.write_text(
        f"#!{sys.executable}\n"
        "import base64,json,os,sys\n"
        "assert sys.argv[1:]==['-m','ai_soc.workspace.model.cli_transport']\n"
        "sys.stdin.buffer.read()\n"
        f"s=os.fstat({slot.fd})\n"
        "body=f'{s.st_dev}:{s.st_ino}'.encode()\n"
        "sys.stdout.write(json.dumps({'status':200,'body':base64.b64encode(body).decode()}))\n"
    )
    executable.chmod(0o700)
    try:
        info = os.fstat(slot.fd)
        monkeypatch.setattr(cli_broker.sys, "executable", str(executable))
        monkeypatch.setattr(cli_broker, "load_credentials", lambda *args, **kwargs: object())
        monkeypatch.setattr(cli_provider, "InferenceBroker", CapturingBroker)
        monkeypatch.setattr(cli_provider, "_request_payload", lambda _pack: b"synthetic")
        monkeypatch.setattr(CodexProfile, "verify", lambda _self: object())
        monkeypatch.setattr(CodexProfile, "prepare_inputs", lambda *args, **kwargs: object())
        monkeypatch.setattr(CodexProfile, "argv", lambda *args, **kwargs: ("synthetic",))

        def run_probe(*args, **kwargs):
            status, body = instances[0]._transport(b"synthetic", {})
            assert status == 200
            assert body == f"{info.st_dev}:{info.st_ino}".encode()
            raise ProbeComplete

        monkeypatch.setattr(cli_provider, "run_bounded", run_probe)
        incident, revision = UUID(int=1), UUID(int=2)
        pack = SimpleNamespace(site_id="site", incident_id=incident, incident_revision_id=revision)
        request = cli_provider.GenerationRequest(pack, "site", incident, revision)
        profile = CodexProfile(auth_path="/synthetic/auth", state_directory=tmp_path / "state")
        with pytest.raises(ProbeComplete):
            cli_provider.CodexCLIProvider(profile).generate(request, slot_fds=(slot.fd,))
    finally:
        slot.close()


def test_slot_rejects_link_added_between_fstat_and_entry_stat(tmp_path, monkeypatch):
    import os

    original = worker.os.stat

    def link_before_entry_stat(path, *args, **kwargs):
        if path == "slot-0.lock" and kwargs.get("follow_symlinks") is False:
            (tmp_path / "added-link").hardlink_to(tmp_path / "slot-0.lock")
        return original(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(worker.os, "stat", link_before_entry_stat)
        with pytest.raises(PermissionError, match="slot_file_changed"):
            worker.acquire_slot(tmp_path)
    assert os.stat(tmp_path / "slot-0.lock").st_nlink == 2


def test_manifest_parent_replaced_by_file_is_changed(tmp_path, monkeypatch):
    from pathlib import Path

    slot = tmp_path / "slot"
    slot.mkdir(mode=0o700)
    parent = tmp_path / "parent"
    parent.mkdir()
    authority = parent / "authority"
    config = worker.ModelConfig(
        frozenset({"site"}), "host", "runtime", slot, authority_path=authority
    )
    authority.write_bytes(worker.authority_material(config, slot.stat()))
    authority.chmod(0o600)
    original = Path.lstat

    def replace_parent(path, *args, **kwargs):
        result = original(path, *args, **kwargs)
        if path == authority:
            parent.rename(tmp_path / "old-parent")
            parent.write_text("replacement")
        return result

    with monkeypatch.context() as patch:
        patch.setattr(Path, "lstat", replace_parent)
        with pytest.raises(PermissionError, match="host_authority_changed"):
            worker.verify_authority(config, slot.stat())


@pytest.mark.parametrize("field", ["mode", "owner", "type"])
def test_slot_rejects_changed_later_entry_metadata(tmp_path, monkeypatch, field):
    import os
    import stat

    original = worker.os.stat

    def changed_entry(path, *args, **kwargs):
        result = original(path, *args, **kwargs)
        if path == "slot-0.lock" and kwargs.get("follow_symlinks") is False:
            values = list(result)
            if field == "mode":
                values[stat.ST_MODE] |= 0o044
            elif field == "owner":
                values[stat.ST_UID] += 1
            else:
                values[stat.ST_MODE] = stat.S_IFIFO | 0o600
            return os.stat_result(values)
        return result

    with monkeypatch.context() as patch:
        patch.setattr(worker.os, "stat", changed_entry)
        with pytest.raises(PermissionError, match="slot_file_changed"):
            worker.acquire_slot(tmp_path)


def test_guardian_rejects_changed_later_entry_link_count(tmp_path, monkeypatch):
    import os
    import stat

    slot = worker.acquire_slot(tmp_path)
    assert slot is not None
    config = worker.ModelConfig(frozenset({"site"}), "host", "runtime", tmp_path)
    original = worker.os.stat

    def two_links(path, *args, **kwargs):
        result = original(path, *args, **kwargs)
        if path == "slot-0.lock" and kwargs.get("follow_symlinks") is False:
            values = list(result)
            values[stat.ST_NLINK] = 2
            return os.stat_result(values)
        return result

    def unreachable():
        raise AssertionError("guardian reached the database boundary")

    try:
        with monkeypatch.context() as patch:
            patch.setattr(worker.os, "stat", two_links)
            with pytest.raises(PermissionError, match="inherited_slot_identity_mismatch"):
                guardian.run_guardian(
                    config=config,
                    slot_fd=slot.fd,
                    legacy_slot_fd=slot.legacy_fd,
                    connect=unreachable,
                    profile=CodexProfile(auth_path="/synthetic/auth"),
                    provider=SimpleNamespace(),
                )
    finally:
        slot.close()


def test_alias_parent_replaced_by_file_is_changed(tmp_path, monkeypatch):
    from pathlib import Path

    slot = tmp_path / "slot"
    slot.mkdir(mode=0o700)
    alias_parent = tmp_path / "alias-parent"
    alias_parent.mkdir()
    alias = alias_parent / "alias"
    alias.symlink_to(slot)
    authority = tmp_path / "authority"
    config = worker.ModelConfig(
        frozenset({"site"}),
        "host",
        "runtime",
        slot,
        authority_path=authority,
        authority_slot_directory=alias,
    )
    authority.write_bytes(worker.authority_material(config, slot.stat()))
    authority.chmod(0o600)
    original = Path.lstat

    def replace_alias_parent(path, *args, **kwargs):
        result = original(path, *args, **kwargs)
        if path == authority and alias_parent.is_dir():
            alias_parent.rename(tmp_path / "old-alias-parent")
            alias_parent.write_text("replacement")
        return result

    with monkeypatch.context() as patch:
        patch.setattr(Path, "lstat", replace_alias_parent)
        with pytest.raises(PermissionError, match="authority_slot_directory_changed"):
            worker.verify_authority(config, slot.stat())
