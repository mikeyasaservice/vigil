"""Retry publisher for durable managed-run queue events."""

from __future__ import annotations

import asyncio
import json
import logging
from contextlib import suppress
from typing import Any

from core.agents.managed_store import ManagedRunStore
from core.agents.queue import enqueue_run

logger = logging.getLogger(__name__)


async def publish_pending_managed_outbox(
    store: ManagedRunStore | None = None,
    *,
    batch_size: int = 100,
) -> int:
    """Publish one bounded batch and acknowledge only after broker acceptance."""
    repository = store or ManagedRunStore()
    published = 0
    for row in repository.pending_outbox(limit=batch_size):
        payload: Any = row["payload"]
        if isinstance(payload, str):
            payload = json.loads(payload)
        if not isinstance(payload, dict):
            raise RuntimeError("managed outbox payload is invalid")
        outbox_id = int(row["outbox_id"])
        await enqueue_run(payload, job_id=f"managed-outbox-{outbox_id}")
        repository.mark_outbox_published(outbox_id)
        published += 1
    return published


async def managed_outbox_publisher(
    *,
    stop: asyncio.Event,
    poll_seconds: float = 1.0,
) -> None:
    """Continuously retry committed events while the managed API is alive."""
    while not stop.is_set():
        try:
            count = await publish_pending_managed_outbox()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - retain the row and retry after backoff
            logger.exception("managed outbox publish failed; committed rows remain pending")
            count = 0
        delay = 0.05 if count else poll_seconds
        with suppress(asyncio.TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=delay)
