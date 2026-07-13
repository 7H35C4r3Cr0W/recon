"""Task-lifecycle + stale-profile-result protection (gui refactor 3/N).

A worker started for profile A must persist its result to A even if the user has since switched to
profile B, and must NOT write to B or replace B's visible interface."""

from pathlib import Path

from pytestqt.qtbot import QtBot

from oscprecon.gui.main_window import MainWindow
from oscprecon.gui.workers import FtpReconResult, LdapReconResult, SmbReconResult
from oscprecon.models import Credential, DiscoveredService, Proto, Target
from oscprecon.profile import Profile


def _two_profiles(tmp_path: Path) -> tuple[Profile, Profile]:
    a = Profile.create(tmp_path / "a", "a", Target(ip="10.0.0.1"))
    b = Profile.create(tmp_path / "b", "b", Target(ip="10.0.0.2"))
    return a, b


def _cred() -> Credential:
    return Credential(username="svc_anon", secret="", source="smb-anon-enum")


def test_stale_smb_result_persists_creds_to_origin_not_active(qtbot: QtBot, tmp_path: Path) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    a, b = _two_profiles(tmp_path)
    window._set_profile(a)
    result = SmbReconResult(summary=["Anonymous access: null session OK"], creds=[_cred()])
    window._set_profile(b)  # user switches to B before A's worker completes
    window._on_smb_done(result, a)  # A's worker finishes — origin is A
    assert [c.username for c in a.credentials()] == ["svc_anon"]  # persisted to A
    assert b.credentials() == []  # B was NOT touched by A's stale result


def test_active_smb_result_persists_and_dedups(qtbot: QtBot, tmp_path: Path) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    a, _ = _two_profiles(tmp_path)
    window._set_profile(a)
    result = SmbReconResult(summary=["ok"], creds=[_cred()])
    window._on_smb_done(result, a)  # origin == active
    window._on_smb_done(result, a)  # re-delivery must not duplicate the credential
    assert [c.username for c in a.credentials()] == ["svc_anon"]


def test_stale_ftp_and_ldap_creds_route_to_origin(qtbot: QtBot, tmp_path: Path) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    a, b = _two_profiles(tmp_path)
    window._set_profile(a)
    ftp_cred = Credential(username="anonymous", secret="", source="ftp-anon-enum")
    ldap_cred = Credential(username="anon-bind", secret="", source="ldap-anon-enum")
    window._set_profile(b)  # B active; A's workers complete late
    window._on_ftp_done(FtpReconResult(summary=["x"], creds=[ftp_cred]), a)
    window._on_ldap_done(LdapReconResult(summary=["y"], creds=[ldap_cred]), a)
    assert {c.username for c in a.credentials()} == {"anonymous", "anon-bind"}  # both on A
    assert b.credentials() == []


def test_stale_probe_mutates_origin_profile_only(qtbot: QtBot, tmp_path: Path) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    a, b = _two_profiles(tmp_path)
    a.set_services([DiscoveredService(8080, Proto.TCP, "http-alt", discovered_at="")])
    window._set_profile(a)
    window._set_profile(b)  # B active; A's probe completes late
    window._probe_done(0, a, a.discovered_services[0])
    assert a.discovered_services[0].service == "http"  # A was re-tagged
    assert Profile.load(b.directory).discovered_services == []  # B on disk unchanged


def test_stale_result_callback_does_not_raise_when_no_profile(qtbot: QtBot, tmp_path: Path) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    a, _ = _two_profiles(tmp_path)
    # no active profile at all; a late A result must still persist to A and not crash the handler
    window._on_smb_done(SmbReconResult(summary=["z"], creds=[_cred()]), a)
    assert len(a.credentials()) == 1


def test_release_is_idempotent(qtbot: QtBot, tmp_path: Path) -> None:
    from oscprecon.gui.workers import SimpleReconWorker

    window = MainWindow()
    qtbot.addWidget(window)
    window._set_profile(Profile.create(tmp_path, "b", Target(ip="10.0.0.5")))
    worker = SimpleReconWorker(window._profile, "ntp", 123)  # not started
    window._tasks.add(worker, "ntp")
    assert window._tasks.active_count == 1
    window._release(worker)
    assert window._tasks.active_count == 0
    window._release(worker)  # second release must be a harmless no-op (no crash, no negative count)
    assert window._tasks.active_count == 0
