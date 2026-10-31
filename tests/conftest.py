import os
import tempfile
import pytest

@pytest.fixture(autouse=True)
def temp_db(monkeypatch):
    with tempfile.TemporaryDirectory() as d:
        monkeypatch.setenv("SENTINEL_DB", os.path.join(d, "test.db"))
        from app.db import init_db
        init_db()
        yield
