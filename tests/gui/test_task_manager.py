from oscprecon.gui.task_manager import DEFAULT_MAX_CONCURRENCY, TaskManager


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


def test_exclusive_blocks_everything() -> None:
    mgr = TaskManager(max_concurrency=4)
    w = _Worker()
    mgr.add(w, "nmap", exclusive=True)
    assert mgr.can_start() is False  # parallel start blocked while exclusive runs
    assert mgr.can_start(exclusive=True) is False  # a second exclusive is blocked too
    mgr.remove(w)
    assert mgr.can_start() is True


def test_exclusive_needs_all_clear() -> None:
    mgr = TaskManager(max_concurrency=4)
    mgr.add(_Worker(), "http")
    assert mgr.can_start() is True  # room for more parallel work
    assert mgr.can_start(exclusive=True) is False  # but exclusive must wait for the clear


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
