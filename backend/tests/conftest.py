"""Pytest configuration for backend tests.

Isolates the main SQLite DB into a temp file and provides live mock API
servers (vulnerable + secure) on ephemeral 127.0.0.1 ports.
"""
from __future__ import annotations

import os
import socket
import sys
import threading

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BACKEND_DIR)
PROJECT_ROOT = os.path.dirname(BACKEND_DIR)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "mock_api"))

# Point the app at a throwaway test DB BEFORE any app.* import
TEST_DB = os.path.join(BACKEND_DIR, "test_privacyguard.db")
os.environ["PG_DATABASE_URL"] = f"sqlite:///{TEST_DB}"

import pytest  # noqa: E402


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def db_engine():
    from app.core.database import Base, engine
    import app.models  # noqa: F401  register models

    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)


@pytest.fixture()
def db(db_engine):
    from app.core.database import SessionLocal

    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture(scope="session")
def mock_servers():
    """Spin up BOTH mock APIs (vulnerable + secure) on localhost, session-wide."""
    import uvicorn
    from server import create_app  # mock_api

    apps = {}
    threads = []
    for mode in ("vulnerable", "secure"):
        port = _free_port()
        server = uvicorn.Server(
            uvicorn.Config(create_app(mode), host="127.0.0.1", port=port, log_level="warning")
        )
        t = threading.Thread(target=server.run, daemon=True)
        t.start()
        apps[mode] = {"url": f"http://127.0.0.1:{port}", "server": server, "thread": t}

    # wait for readiness
    import httpx

    for mode, info in apps.items():
        for _ in range(100):
            try:
                if httpx.get(info["url"] + "/health", timeout=0.5).status_code == 200:
                    break
            except httpx.HTTPError:
                import time

                time.sleep(0.1)
        else:
            raise RuntimeError(f"mock {mode} server did not start")

    yield {mode: info["url"] for mode, info in apps.items()}

    for info in apps.values():
        info["server"].should_exit = True
        info["thread"].join(timeout=5)
