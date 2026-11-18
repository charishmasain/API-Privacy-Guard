import os
import sys

import pytest

# Make the mock_api package importable regardless of pytest's rootdir.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient  # noqa: E402

from server import create_app  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def seeded_db():
    from database import init_mock_db

    init_mock_db(force=True)


@pytest.fixture(scope="session")
def vulnerable_client():
    return TestClient(create_app("vulnerable"))


@pytest.fixture(scope="session")
def secure_client():
    return TestClient(create_app("secure"))


ALICE = {"Authorization": "Bearer mock-token-alice-3f8a9c"}
BOB = {"Authorization": "Bearer mock-token-bob-77d1e0"}
