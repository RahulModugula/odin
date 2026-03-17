from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def python_good_code() -> str:
    return (FIXTURES_DIR / "python_good.py").read_text()


@pytest.fixture
def python_bad_code() -> str:
    return (FIXTURES_DIR / "python_bad.py").read_text()


@pytest.fixture
def javascript_bad_code() -> str:
    return (FIXTURES_DIR / "javascript_bad.js").read_text()
