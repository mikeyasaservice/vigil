from __future__ import annotations

from fastapi import HTTPException
import pytest

from services.security import app as security_app


class FakeDatabase:
    def __init__(self, healthy: bool = True) -> None:
        self.healthy = healthy
        self.initialized = False
        self.closed = False

    def initialize(self) -> None:
        self.initialized = True

    def health_check(self) -> bool:
        return self.healthy

    def close(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_security_lifespan_initializes_and_closes_database(monkeypatch: pytest.MonkeyPatch) -> None:
    database = FakeDatabase()
    monkeypatch.setattr(security_app, "get_db_manager", lambda: database)

    async with security_app.lifespan(security_app.app):
        assert database.initialized is True
        assert database.closed is False

    assert database.closed is True


@pytest.mark.asyncio
async def test_security_lifespan_fails_closed_when_database_is_unhealthy(monkeypatch: pytest.MonkeyPatch) -> None:
    database = FakeDatabase(healthy=False)
    monkeypatch.setattr(security_app, "get_db_manager", lambda: database)

    with pytest.raises(RuntimeError, match="database is unavailable"):
        async with security_app.lifespan(security_app.app):
            pass

    assert database.closed is True


def test_security_health_reflects_durable_state(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(security_app, "get_db_manager", lambda: FakeDatabase(healthy=False))

    with pytest.raises(HTTPException) as unavailable:
        security_app.healthz()

    assert unavailable.value.status_code == 503
