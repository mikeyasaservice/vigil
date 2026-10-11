from __future__ import annotations

from unittest.mock import AsyncMock, Mock

import pytest

from core.agents import managed_outbox


@pytest.mark.asyncio
async def test_publisher_uses_deterministic_id_then_acknowledges(monkeypatch):
    store = Mock()
    store.pending_outbox.return_value = [
        {"outbox_id": 17, "payload": {"run_id": "run-1", "run_kind": "investigate"}}
    ]
    enqueue = AsyncMock(return_value="managed-outbox-17")
    monkeypatch.setattr(managed_outbox, "enqueue_run", enqueue)

    assert await managed_outbox.publish_pending_managed_outbox(store) == 1

    enqueue.assert_awaited_once_with(
        {"run_id": "run-1", "run_kind": "investigate"},
        job_id="managed-outbox-17",
    )
    store.mark_outbox_published.assert_called_once_with(17)


@pytest.mark.asyncio
async def test_publisher_does_not_acknowledge_failed_publish(monkeypatch):
    store = Mock()
    store.pending_outbox.return_value = [
        {"outbox_id": 18, "payload": {"run_id": "run-2", "run_kind": "investigate"}}
    ]
    monkeypatch.setattr(
        managed_outbox,
        "enqueue_run",
        AsyncMock(side_effect=ConnectionError("broker unavailable")),
    )

    with pytest.raises(ConnectionError, match="broker unavailable"):
        await managed_outbox.publish_pending_managed_outbox(store)

    store.mark_outbox_published.assert_not_called()
