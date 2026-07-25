from oscprecon.gui.task_manager import (
    BATTERY_LANE,
    DEFAULT_MAX_CONCURRENCY,
    NMAP_LANE,
    TOOL_LANE,
    TaskManager,
)


class _Worker:
    def __init__(self) -> None:
        self.cancelled = False

    def cancel(self) -> None:
        self.cancelled = True


class _NoCancelWorker:
    pass


def test_bound_limits_parallel_starts() -> None:
    mgr = TaskManager(max_concurrency=2)
    assert mgr.can_start() is True
    mgr.add(_Worker(), "a")
    assert mgr.can_start() is True
    mgr.add(_Worker(), "b")
    assert mgr.can_start() is False  # at capacity (2)
    assert mgr.active_count == 2


def test_remove_frees_a_slot() -> None:
    mgr = TaskManager(max_concurrency=1)
    w = _Worker()
    mgr.add(w, "a")
    assert mgr.can_start() is False
    mgr.remove(w)
    assert mgr.can_start() is True
    assert mgr.active_count == 0


def test_the_battery_lane_holds_one_run_but_blocks_nothing_else() -> None:
    # the recon battery owns the profile's staged output, so only ONE runs — but it must not stop
    # an ad-hoc nmap or a service scan, which is the whole point of the lane model.
    mgr = TaskManager(6)
    mgr.add(_Worker(), "nmap", lane=BATTERY_LANE)
    assert mgr.can_start(lane=BATTERY_LANE) is False
    assert mgr.can_start(lane=NMAP_LANE) is True
    assert mgr.can_start(lane=TOOL_LANE) is True


def test_a_tool_task_does_not_block_the_battery() -> None:
    mgr = TaskManager(6)
    mgr.add(_Worker(), "http:80", lane=TOOL_LANE)
    assert mgr.can_start(lane=BATTERY_LANE) is True


def test_the_nmap_lane_has_its_own_cap() -> None:
    mgr = TaskManager(6)
    cap = mgr.lane_cap(NMAP_LANE)
    assert cap >= 2  # a full sweep + a vuln scan together, at minimum
    for i in range(cap):
        assert mgr.can_start(lane=NMAP_LANE) is True
        mgr.add(_Worker(), f"scan-{i}", lane=NMAP_LANE)
    assert mgr.can_start(lane=NMAP_LANE) is False
    assert mgr.can_start(lane=TOOL_LANE) is True


def test_why_blocked_names_the_bound_that_was_hit() -> None:
    mgr = TaskManager(6)
    mgr.add(_Worker(), "nmap", lane=BATTERY_LANE)
    assert "full recon" in mgr.why_blocked(BATTERY_LANE)


def test_tags_are_unique_even_for_the_same_label() -> None:
    mgr = TaskManager(6)
    a = mgr.add(_Worker(), "http:80")
    b = mgr.add(_Worker(), "http:80")
    assert a.tag != b.tag


def test_changed_signal_fires_on_add_and_remove(qtbot: object) -> None:
    mgr = TaskManager()
    seen: list[int] = []
    mgr.changed.connect(lambda: seen.append(mgr.active_count))
    w = _Worker()
    mgr.add(w, "a")
    mgr.remove(w)
    assert seen == [1, 0]


def test_cancel_all_only_touches_cancellables() -> None:
    mgr = TaskManager()
    cancellable = _Worker()
    plain = _NoCancelWorker()
    mgr.add(cancellable, "a")
    mgr.add(plain, "b")
    mgr.cancel_all()  # must not raise on the worker lacking cancel()
    assert cancellable.cancelled is True


def test_default_bound() -> None:
    assert TaskManager().max_concurrency == DEFAULT_MAX_CONCURRENCY
