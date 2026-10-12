from types import SimpleNamespace

import pytest

from core.llm.gateway import gateway


@pytest.mark.parametrize(
    ("url", "ssl", "username", "password", "database"),
    [
        ("redis://localhost:6379/0", False, None, None, 0),
        ("rediss://tenant-worker:p%40ss@cache.example:6380/3", True, "tenant-worker", "p@ss", 3),
    ],
)
def test_redis_settings_preserves_dsn_security_properties(
    monkeypatch: pytest.MonkeyPatch,
    url: str,
    ssl: bool,
    username: str | None,
    password: str | None,
    database: int,
) -> None:
    monkeypatch.setattr(gateway, "get_settings", lambda: SimpleNamespace(redis_url=url))

    settings = gateway.redis_settings()

    assert settings.ssl is ssl
    assert settings.username == username
    assert settings.password == password
    assert settings.database == database
