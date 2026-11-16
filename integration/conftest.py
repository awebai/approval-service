"""Disposable real PostgreSQL resources for placed integration tests."""

import os
import uuid

import psycopg
import pytest

from approval_service.store import Store


@pytest.fixture
def store():
    dsn = os.environ["APPROVAL_TEST_DATABASE_URL"]
    schema = "approval_test_" + uuid.uuid4().hex
    db = Store(dsn, schema=schema)
    db.migrate()
    yield db
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute('DROP SCHEMA "' + schema + '" CASCADE')
