from __future__ import annotations

from services.connector import app as connector


def test_managed_recall_uses_execution_identity_for_audit(monkeypatch) -> None:
    seen: dict[str, object] = {}

    def fake_recall(_connection, args, *, max_rows, timeout_ms):
        seen.update(args)
        seen.update(max_rows=max_rows, timeout_ms=timeout_ms)
        return {"keys": args["entity_keys"], "sightings": []}

    monkeypatch.setattr(connector, "managed_recall_entity", fake_recall)
    monkeypatch.setattr(connector, "_connection", lambda: _Connection())
    body = connector.ConnectorInvokeRequest(
        tool="recall_entity",
        args={
            "entity_keys": ["host:alpha"],
            "as_of": "2026-10-12T00:00:00Z",
            "caller_kind": "forged",
            "caller_id": "forged",
        },
        tenant_id="tenant-a",
        execution_id="execution-a",
        max_rows=1,
        timeout_ms=10_000,
    )

    assert connector._read(body) == [{"keys": ["host:alpha"], "sightings": []}]
    assert seen["caller_kind"] == "execution"
    assert seen["caller_id"] == "execution-a"
    assert seen["entity_keys"] == ["host:alpha"]
    assert seen["max_rows"] == 1
    assert seen["timeout_ms"] == 10_000


def test_managed_recall_rejects_missing_entity_key(monkeypatch) -> None:
    def reject(_connection, _args, *, max_rows, timeout_ms):
        raise TypeError("recall_entity: a call needs entity_keys")

    monkeypatch.setattr(connector, "managed_recall_entity", reject)
    monkeypatch.setattr(connector, "_connection", lambda: _Connection())
    body = connector.ConnectorInvokeRequest(
        tool="recall_entity",
        args={},
        tenant_id="tenant-a",
        execution_id="execution-a",
        max_rows=1,
        timeout_ms=10_000,
    )

    try:
        connector._read(body)
    except TypeError as exc:
        assert "entity_keys" in str(exc)
    else:
        raise AssertionError("missing recall keys were accepted")


class _Connection:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False
