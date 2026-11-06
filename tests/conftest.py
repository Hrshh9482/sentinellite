"""
conftest.py — shared pytest fixtures.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Make sure src/ is on the path so tests can import sentinellite without install
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest

from sentinellite.storage import init_db


@pytest.fixture
def tmp_db(tmp_path):
    """Return an initialised SQLite connection in a temp directory."""
    conn = init_db(tmp_path / "test.db")
    yield conn
    conn.close()
