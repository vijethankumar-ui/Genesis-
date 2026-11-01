"""Pytest fixtures for the GENESIS attack lab.

Importing the backend requires the environment (.env) to be loaded and the
working directory to be the worktree root, because the app resolves several
SQLite paths (vault index, identity registry, budgets) relative to CWD. We do
that at import time, before any ``app.*`` module is imported.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

# security_testing/ -> worktree root
ROOT = Path(__file__).resolve().parent.parent
os.chdir(ROOT)
load_dotenv(ROOT / ".env", override=True)

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture(scope="session")
def client() -> TestClient:
    """A TestClient bound to the integrated GENESIS app."""
    from app.main import app

    return TestClient(app)
