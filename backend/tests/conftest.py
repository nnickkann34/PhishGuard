"""Shared pytest fixtures: a TestClient backed by a temporary database."""
from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest


@pytest.fixture()
def client(tmp_path, monkeypatch):
    # Point the app at a throwaway SQLite file and reset cached settings so
    # each test gets a clean, isolated database and a known configuration.
    db = tmp_path / "test.db"
    monkeypatch.setenv("PG_DATABASE_URL", f"sqlite:///{db.as_posix()}")
    monkeypatch.setenv("PG_DOS_PROTECTION", "true")
    monkeypatch.setenv("PG_INSECURE_SQL_DEMO", "false")
    monkeypatch.setenv("PG_NORMALISE_HOMOGLYPHS", "true")

    from app.config import get_settings
    get_settings.cache_clear()

    # Import inside the fixture so the env vars above are read at construction.
    from fastapi.testclient import TestClient
    from app.main import app

    with TestClient(app) as c:
        yield c

    get_settings.cache_clear()


@pytest.fixture()
def session_headers():
    return {"X-Session-ID": str(uuid.uuid4())}
