"""Disposable real PostgreSQL resources for placed integration tests."""

import os
import uuid

import pytest_asyncio

from approval_service.store import Store


@pytest_asyncio.fixture
async def store():
    dsn = os.environ["APPROVAL_TEST_DATABASE_URL"]
    schema = "approval_test_" + uuid.uuid4().hex
    db = Store(dsn, schema=schema, min_connections=1, max_connections=2)
    await db.connect()
    try:
        await db.migrate()
        yield db
    finally:
        # This fixture owns this fresh schema; no other service state is touched.
        await db.db.execute('DROP SCHEMA "' + schema + '" CASCADE')
        await db.close()
