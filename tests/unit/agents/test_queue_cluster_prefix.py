import asyncio

from core.agents import queue


def test_run_queue_uses_one_cluster_hash_slot(monkeypatch):
    captured = {}

    class FakeQueue:
        def __init__(self, name, options):
            captured.update(name=name, options=options)

    monkeypatch.setattr(queue, "Queue", FakeQueue)

    async def build():
        queue._queues.clear()
        return queue._run_queue()

    asyncio.run(build())

    assert captured["name"] == "agent-runs"
    assert captured["options"]["prefix"] == "{bull}"
