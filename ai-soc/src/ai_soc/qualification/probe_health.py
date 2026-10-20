"""Run a long probe beside a minimal same-image ECS health responder."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


class _ProbeState:
    def __init__(self, ready_file: Path) -> None:
        self.ready_file = ready_file
        self.child: subprocess.Popen[bytes] | None = None

    def ready(self) -> bool:
        return self.child is not None and self.child.poll() is None and self.ready_file.is_file()


def run_probe(command: list[str], *, timeout_seconds: int, ready_file: Path) -> int:
    if not command or timeout_seconds < 1 or timeout_seconds > 900:
        raise ValueError("a command and a 1..900 second timeout are required")
    ready_file.unlink(missing_ok=True)
    state = _ProbeState(ready_file)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            healthy = self.path == "/health/live" or (
                self.path == "/health/ready" and state.ready()
            )
            self.send_response(200 if healthy else 503)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}' if healthy else b'{"status":"not-ready"}')

        def log_message(self, format: str, *args: Any) -> None:
            return

    server = ThreadingHTTPServer(("0.0.0.0", 8000), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, name="qualification-health", daemon=True).start()
    child: subprocess.Popen[bytes] | None = None
    try:
        child = subprocess.Popen(
            command, env={**os.environ, "AI_SOC_PROBE_READY_FILE": str(ready_file)}
        )
        state.child = child
        try:
            returncode = child.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
            return 124
        return returncode
    finally:
        state.child = None
        server.shutdown()
        server.server_close()
        ready_file.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout-seconds", type=int, required=True)
    parser.add_argument("--ready-file", type=Path, default=Path("/tmp/qualification-probe-ready"))
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("provide a command after --")
    return run_probe(command, timeout_seconds=args.timeout_seconds, ready_file=args.ready_file)


if __name__ == "__main__":
    sys.exit(main())
