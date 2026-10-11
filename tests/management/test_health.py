from __future__ import annotations

import pytest
from fastapi import HTTPException

from services.management import app as management_app
from services.management.store import ManagementUnavailable


class ReadyStore:
    def check_ready(self) -> None:
        return None


class UnavailableStore:
    def check_ready(self) -> None:
        raise ManagementUnavailable("database unavailable")


def test_liveness_does_not_depend_on_database() -> None:
    assert management_app.livez() == {"status": "ok"}


def test_readiness_checks_database(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(management_app, "_store", lambda: ReadyStore())
    assert management_app.readyz() == {"status": "ok"}
    monkeypatch.setattr(management_app, "_store", lambda: UnavailableStore())
    with pytest.raises(HTTPException) as raised:
        management_app.readyz()
    assert raised.value.status_code == 503
