"""Workers were extracted from main_window into oscprecon.gui.workers; prove they import + build
from the new location, keep their signal signatures, and remain re-exported from main_window."""

from pathlib import Path

from PySide6.QtCore import QThread
from pytestqt.qtbot import QtBot

from oscprecon.gui import main_window as mw
from oscprecon.gui.workers import (
    CancellableThread,
    CommandWorker,
    DnsReconWorker,
    FtpReconWorker,
    LdapReconWorker,
    NmapWorker,
    SearchsploitWorker,
    SimpleReconWorker,
    SmbReconWorker,
    SshReconWorker,
)
from oscprecon.models import Target
from oscprecon.profile import Profile

_CANCELLABLE = [
    NmapWorker,
    CommandWorker,
    SmbReconWorker,
    FtpReconWorker,
    SshReconWorker,
    DnsReconWorker,
    LdapReconWorker,
    SimpleReconWorker,
]


def test_workers_still_reexported_from_main_window() -> None:
    # existing tests / call sites do `mw.SimpleReconWorker`, `from ...main_window import ...`
    for name in (
        "CancellableThread",
        "NmapWorker",
        "CommandWorker",
        "SmbReconWorker",
        "FtpReconWorker",
        "SshReconWorker",
        "DnsReconWorker",
        "LdapReconWorker",
        "SimpleReconWorker",
        "SearchsploitWorker",
    ):
        assert getattr(mw, name) is not None
    assert mw.CancellableThread is CancellableThread  # same object, not a copy


def test_recon_workers_are_cancellable_threads() -> None:
    assert issubclass(CancellableThread, QThread)
    for cls in _CANCELLABLE:
        assert issubclass(cls, CancellableThread)
    assert issubclass(SearchsploitWorker, QThread)  # EDB lookup is not cancellable by design


def test_workers_instantiate_and_expose_signals(qtbot: QtBot, tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    built = [
        NmapWorker(prof),
        CommandWorker("nmap -p80 10.10.10.5", tmp_path / "o.txt"),
        SmbReconWorker(prof, "full"),
        FtpReconWorker(prof, "quick", 21),
        SshReconWorker(prof, 22),
        DnsReconWorker(prof, "corp.local", 53),
        LdapReconWorker(prof, "", 389),
        SimpleReconWorker(prof, "ntp", 123),
        SearchsploitWorker("nginx", "1.18", tmp_path / "edb.json", 1),
    ]
    for worker in built:
        # signals preserved after the move
        assert hasattr(worker, "done")
        assert hasattr(type(worker), "run")
        if isinstance(worker, CancellableThread):
            assert hasattr(worker, "cancel")
            assert hasattr(worker, "failed")
            assert hasattr(worker, "line")


def test_cancel_sets_the_shared_event(qtbot: QtBot, tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    worker = SimpleReconWorker(prof, "ntp", 123)
    assert not worker._cancel.is_set()
    worker.cancel()
    assert worker._cancel.is_set()  # cancel() still threads into shell.run(cancel=...)


def test_worker_retains_its_own_profile(tmp_path: Path) -> None:
    a = Profile.create(tmp_path / "a", "a", Target(ip="10.0.0.1"))
    b = Profile.create(tmp_path / "b", "b", Target(ip="10.0.0.2"))
    worker = SmbReconWorker(a, "full")
    assert worker._profile is a and worker._profile is not b  # ownership captured at construction
