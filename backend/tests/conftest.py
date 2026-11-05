"""Test setup. Tests run against a separate Postgres database named '<dbname>_test' that is created
automatically. The development database is never touched."""
import os

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from app.config import get_settings

_base_url = make_url(os.environ.get("DATABASE_URL") or get_settings().database_url)
_test_db_name = os.environ.get("TEST_DB_NAME") or f"{_base_url.database}_test"
_test_url = _base_url.set(database=_test_db_name)
assert _test_db_name.endswith("_test"), "Refusing to run tests against a non-test database"


def _ensure_test_database() -> None:
    admin = create_engine(_base_url.set(database="postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        exists = conn.scalar(text("SELECT 1 FROM pg_database WHERE datname = :n"), {"n": _test_db_name})
        if not exists:
            conn.execute(text(f'CREATE DATABASE "{_test_db_name}"'))
    admin.dispose()


_ensure_test_database()
os.environ["DATABASE_URL"] = _test_url.render_as_string(hide_password=False)
get_settings.cache_clear()

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.database import Base, engine, init_db  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture(autouse=True)
def clean_database():
    init_db()
    assert engine.url.database.endswith("_test")
    with engine.begin() as conn:
        tables = ", ".join(t.name for t in reversed(Base.metadata.sorted_tables))
        conn.execute(text(f"TRUNCATE {tables} RESTART IDENTITY CASCADE"))
    yield


@pytest.fixture()
def client():
    with TestClient(app) as test_client:
        yield test_client
