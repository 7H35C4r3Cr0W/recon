"""LogPump backpressure: a flood of engine log lines is BOUNDED (deque cap) and published in
rate-limited batches with a 'suppressed' overflow count — never one coroutine per line."""
from __future__ import annotations

import asyncio

import pytest

from nabu_agent.events.schema import RunEventType
from nabu_agent.services.runs import LogPump

pytestmark = pytest.mark.asyncio


async def test_logpump_bounds_batches_and_counts_overflow():
    events: list[tuple] = []

    async def publish(t, data):
        events.append((t, data))

    pump = LogPump("r1", publish, cap=100, batch=50, interval=0.05)
    task = asyncio.create_task(pump.drain())
    for i in range(500):          # flood far past the cap, synchronously (before any drain runs)
        pump.feed(f"line {i}")
    await asyncio.sleep(0.12)      # let the drain flush
    pump.stop()
    await pump.flush()
    task.cancel()

    assert events, "expected batched log events"
    assert all(t == RunEventType.LOG_LINE for t, _ in events)
    assert all(len(d["lines"]) <= 50 for _, d in events)          # each batch respects the cap
    total = sum(len(d["lines"]) for _, d in events)
    suppressed = sum(d.get("suppressed", 0) for _, d in events)
    assert total <= 100 and total > 0                              # never more than the buffer cap
    assert suppressed >= 400                                       # 500 fed into a 100-cap buffer


async def test_logpump_final_flush_emits_remaining():
    events: list[tuple] = []

    async def publish(t, data):
        events.append((t, data))

    pump = LogPump("r2", publish, cap=100, batch=50, interval=5.0)  # long interval → rely on flush()
    pump.feed("only line")
    await pump.flush()
    assert events and events[0][1]["lines"] == ["only line"]
