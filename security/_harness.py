"""Shared helpers: start the API in a chosen configuration and tear it down.

Each demo needs the server running twice with different PG_* settings. Rather
than ask the marker to restart it by hand, we launch uvicorn ourselves on a
spare port, wait for /api/health, hand back the base URL, and shut it down
afterwards.
"""
from __future__ import annotations

import contextlib
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent / "backend"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_health(base: str, timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{base}/api/health", timeout=2) as r:
                if r.status == 200:
                    return
        except (urllib.error.URLError, ConnectionError, OSError) as exc:  # not up yet
            last = exc
            time.sleep(0.25)
    raise RuntimeError(f"API did not become healthy at {base}: {last}")


@contextlib.contextmanager
def running_api(label: str, env_overrides: dict[str, str]):
    """Context manager yielding the base URL of a freshly started API."""
    port = _free_port()
    env = os.environ.copy()
    env.update({k: str(v) for k, v in env_overrides.items()})
    # Each run gets its own throwaway SQLite file so history demos start clean.
    db = BACKEND_DIR / "data" / f"demo_{port}.db"
    env["PG_DATABASE_URL"] = f"sqlite:///{db.as_posix()}"
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--port", str(port), "--no-server-header"],
        cwd=BACKEND_DIR, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        _wait_for_health(base)
        print(f"  [{label}] API up on {base}")
        yield base
    finally:
        proc.terminate()
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=5)
        if proc.poll() is None:
            proc.kill()
        with contextlib.suppress(FileNotFoundError):
            db.unlink()


def rule(title: str) -> None:
    print("\n" + "=" * 68)
    print(title)
    print("=" * 68)
