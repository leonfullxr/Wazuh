"""Bounded Linux process execution with process-group cleanup."""

from __future__ import annotations

import hashlib
import os
import selectors
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import IO


@dataclass(frozen=True, slots=True)
class ProcessCapture:
    """Ephemeral bounded captures; callers must never persist or log raw bytes."""

    returncode: int
    stdout: bytes
    stderr: bytes
    stdout_sha256: str
    stderr_sha256: str
    elapsed_seconds: float


class ProcessFailure(RuntimeError):
    """Safe process error containing only static classification and bounded metadata."""

    def __init__(
        self,
        code: str,
        *,
        stdout_sha256: str = "",
        stderr_sha256: str = "",
        stdout_bytes: int = 0,
        stderr_bytes: int = 0,
        stdout_truncated: bool = False,
        stderr_truncated: bool = False,
    ):
        super().__init__(code)
        self.code = code
        self.stdout_sha256 = stdout_sha256
        self.stderr_sha256 = stderr_sha256
        self.stdout_bytes = stdout_bytes
        self.stderr_bytes = stderr_bytes
        self.stdout_truncated = stdout_truncated
        self.stderr_truncated = stderr_truncated


def run_bounded(
    argv: tuple[str, ...],
    stdin: bytes,
    *,
    timeout_seconds: float = 120.0,
    stdout_limit: int = 262144,
    stderr_limit: int = 16384,
    stdin_limit: int = 131072,
    cancel_event: threading.Event | None = None,
    pass_fds: tuple[int, ...] = (),
) -> ProcessCapture:
    if len(stdin) > stdin_limit:
        raise ProcessFailure("input_too_large")
    if (
        not 0 < timeout_seconds <= 120
        or not 0 < stdin_limit <= 131072
        or not 0 < stdout_limit <= 262144
        or not 0 < stderr_limit <= 16384
    ):
        raise ProcessFailure("invalid_process_bounds")
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            close_fds=True,
            pass_fds=pass_fds,
            start_new_session=True,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
            cwd="/tmp",
            bufsize=0,
        )
    except OSError:
        raise ProcessFailure("process_start_failed") from None
    assert process.stdin is not None and process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    streams: dict[int, IO[bytes]] = {
        process.stdout.fileno(): process.stdout,
        process.stderr.fileno(): process.stderr,
        process.stdin.fileno(): process.stdin,
    }
    out = bytearray()
    err = bytearray()
    input_offset = 0
    process_group_killed = False
    try:
        for stream in (process.stdout, process.stderr, process.stdin):
            os.set_blocking(stream.fileno(), False)
        selector.register(process.stdout.fileno(), selectors.EVENT_READ, "stdout")
        selector.register(process.stderr.fileno(), selectors.EVENT_READ, "stderr")
        selector.register(process.stdin.fileno(), selectors.EVENT_WRITE, "stdin")
        while selector.get_map():
            elapsed = time.monotonic() - started
            if elapsed >= timeout_seconds:
                raise _failure("timeout", out, err)
            if cancel_event is not None and cancel_event.is_set():
                raise _failure("cancelled", out, err)
            if process.poll() is not None and not process_group_killed:
                _kill_group(process.pid)
                process_group_killed = True
            events = selector.select(min(0.05, timeout_seconds - elapsed))
            for key, _ in events:
                fd = key.fd
                stream = streams[fd]
                kind = key.data
                if kind == "stdin":
                    if input_offset >= len(stdin):
                        selector.unregister(fd)
                        stream.close()
                        continue
                    try:
                        wrote = os.write(
                            stream.fileno(), stdin[input_offset : input_offset + 16384]
                        )
                    except (BrokenPipeError, ConnectionResetError):
                        selector.unregister(fd)
                        stream.close()
                    else:
                        input_offset += wrote
                    continue
                sink = out if kind == "stdout" else err
                limit = stdout_limit if kind == "stdout" else stderr_limit
                try:
                    chunk = os.read(stream.fileno(), min(16384, limit + 1 - len(sink)))
                except OSError:
                    chunk = b""
                if not chunk:
                    selector.unregister(fd)
                    stream.close()
                    continue
                sink.extend(chunk)
                if len(sink) > limit:
                    raise _failure(f"{kind}_limit", out, err)
            if process.poll() is not None and not events and selector.get_map():
                # A descendant may retain a pipe after its parent exits.
                if process_group_killed:
                    continue
        try:
            returncode = process.wait(
                timeout=max(0.1, timeout_seconds - (time.monotonic() - started))
            )
        except subprocess.TimeoutExpired:
            raise _failure("timeout", out, err) from None
        return ProcessCapture(
            returncode, bytes(out), bytes(err), _hash(out), _hash(err), time.monotonic() - started
        )
    except BaseException as error:
        _kill_group(process.pid)
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            _kill_group(process.pid, signal.SIGKILL)
            process.wait()
        if isinstance(error, ProcessFailure):
            raise
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        raise _failure("process_io_failed", out, err) from None
    finally:
        selector.close()
        for stream in (process.stdin, process.stdout, process.stderr):
            try:
                stream.close()
            except OSError:
                pass


def _kill_group(pgid: int, sig: int = signal.SIGKILL) -> None:
    try:
        os.killpg(pgid, sig)
    except ProcessLookupError:
        pass


def _hash(data: bytearray) -> str:
    return hashlib.sha256(data).hexdigest()


def _failure(code: str, stdout: bytearray, stderr: bytearray) -> ProcessFailure:
    return ProcessFailure(
        code,
        stdout_sha256=_hash(stdout),
        stderr_sha256=_hash(stderr),
        stdout_bytes=len(stdout),
        stderr_bytes=len(stderr),
        stdout_truncated=code == "stdout_limit",
        stderr_truncated=code == "stderr_limit",
    )
