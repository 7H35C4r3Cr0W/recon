"""Run admission control — one active run per project (Redis mutex) + a global concurrent-run
ceiling. This is what keeps two runs from racing one project's Profile and stops a burst of launches
from exhausting the worker pool."""
from __future__ import annotations

import fakeredis.aioredis
import pytest
from nabu_agent import bus
from nabu_agent.orchestration import admission

pytestmark = pytest.mark.asyncio


@pytest.fixture
def _redis():
    bus.set_client(fakeredis.aioredis.FakeRedis(decode_responses=True))
    yield
    bus.set_client(None)


async def test_one_active_run_per_project(_redis):
    assert await admission.acquire_run_slot("p1", "/ws/p1") is True
    # a second run on the same project (same Profile dir) is refused while the first holds the slot
    assert await admission.acquire_run_slot("p1", "/ws/p1") is False
    # a different project is unaffected
    assert await admission.acquire_run_slot("p2", "/ws/p2") is True
    # releasing frees the project for the next run
    await admission.release_run_slot("p1", "/ws/p1")
    assert await admission.acquire_run_slot("p1", "/ws/p1") is True


async def test_global_ceiling(_redis):
    for i in range(4):
        assert await admission.acquire_run_slot(f"p{i}", f"/ws/p{i}", ceiling=4) is True
    # the 5th distinct run is over the ceiling and refused (and does NOT hold p4's mutex)
    assert await admission.acquire_run_slot("p4", "/ws/p4", ceiling=4) is False
    await admission.release_run_slot("p0", "/ws/p0")
    assert await admission.acquire_run_slot("p4", "/ws/p4", ceiling=4) is True


async def test_release_never_goes_negative(_redis):
    await admission.acquire_run_slot("p1", "/ws/p1")
    await admission.release_run_slot("p1", "/ws/p1")
    await admission.release_run_slot("p1", "/ws/p1")  # double release must not corrupt the counter
    for i in range(4):
        assert await admission.acquire_run_slot(f"q{i}", f"/ws/q{i}", ceiling=4) is True
