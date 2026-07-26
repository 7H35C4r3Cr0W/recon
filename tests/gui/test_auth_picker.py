"""The "Run as" picker on the service panels — the GUI half of credentialed recon.

The operator's complaint was concrete: "you only have smb anon or guest to check from, but I don't
have an option to take the creds I may have found". These tests pin the control that fixes it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("PySide6")

from pytestqt.qtbot import QtBot  # noqa: E402

from oscprecon.gui.widgets.auth_picker import AuthPicker  # noqa: E402
from oscprecon.gui.widgets.ftp_panel import FtpPanel  # noqa: E402
from oscprecon.gui.widgets.ldap_panel import LdapPanel  # noqa: E402
from oscprecon.gui.widgets.smb_panel import SmbPanel  # noqa: E402
from oscprecon.models import Credential, Target  # noqa: E402
from oscprecon.profile import Profile  # noqa: E402
from oscprecon.recon_auth import ReconAuth  # noqa: E402


def _profile(tmp_path: Path, *creds: Credential) -> Profile:
    profile = Profile.create(tmp_path, "box", Target(ip="10.10.10.5", hostname="active.htb"))
    for cred in creds:
        profile.add_credential(cred)
    profile.save()
    return profile


def _cred(username: str = "svc_account", secret: str = "Ticketmaster1968") -> Credential:
    return Credential(username=username, secret=secret, domain="active.htb", source="http-leak")


def test_anonymous_is_the_default(qtbot: QtBot, tmp_path: Path) -> None:
    picker = AuthPicker()
    qtbot.addWidget(picker)
    picker.set_credentials([_cred()])
    assert picker.current_auth() is None  # anonymous stays the first move


def test_a_vault_credential_can_be_selected(qtbot: QtBot) -> None:
    picker = AuthPicker()
    qtbot.addWidget(picker)
    picker.set_credentials([_cred()])
    picker._combo.setCurrentIndex(1)
    auth = picker.current_auth()
    assert auth is not None and auth.username == "svc_account"


def test_a_credential_with_no_secret_is_not_offered(qtbot: QtBot) -> None:
    # an empty secret would build `-p ''` and read as a working credential when it is a placeholder
    picker = AuthPicker()
    qtbot.addWidget(picker)
    picker.set_credentials([_cred(secret="")])
    assert not picker.has_credentials()


def test_a_vault_refresh_keeps_the_operator_choice(qtbot: QtBot) -> None:
    # a new credential landing mid-run must not silently switch the next run back to anonymous
    picker = AuthPicker()
    qtbot.addWidget(picker)
    picker.set_credentials([_cred()])
    picker._combo.setCurrentIndex(1)
    picker.set_credentials([_cred("administrator", "Passw0rd"), _cred()])
    auth = picker.current_auth()
    assert auth is not None and auth.username == "svc_account"


def test_smb_panel_emits_the_selected_identity(qtbot: QtBot, tmp_path: Path) -> None:
    panel = SmbPanel()
    qtbot.addWidget(panel)
    panel.set_profile(_profile(tmp_path, _cred()))
    captured: list[tuple[str, object]] = []
    panel.recon_requested.connect(lambda mode, auth: captured.append((mode, auth)))

    panel._auth._combo.setCurrentIndex(2)  # 0 anonymous, 1 guest, 2 the vault credential
    panel._full.click()

    assert captured[0][0] == "full"
    auth = captured[0][1]
    assert isinstance(auth, ReconAuth) and auth.username == "svc_account"


def test_smb_panel_button_says_who_it_will_run_as(qtbot: QtBot, tmp_path: Path) -> None:
    # picking a credential and pressing an unchanged button looks exactly like the anonymous run
    panel = SmbPanel()
    qtbot.addWidget(panel)
    panel.set_profile(_profile(tmp_path, _cred()))
    assert panel._full.text() == "Run full SMB recon"
    panel._auth._combo.setCurrentIndex(2)
    assert "svc_account" in panel._full.text()


def test_smb_null_and_guest_buttons_stay_anonymous(qtbot: QtBot, tmp_path: Path) -> None:
    panel = SmbPanel()
    qtbot.addWidget(panel)
    panel.set_profile(_profile(tmp_path, _cred()))
    captured: list[object] = []
    panel.recon_requested.connect(lambda _mode, auth: captured.append(auth))

    panel._auth._combo.setCurrentIndex(2)
    panel._null.click()
    panel._guest.click()

    assert captured[0] is None  # "Just check null session" means null, whatever is picked
    assert isinstance(captured[1], ReconAuth) and captured[1].kind == "guest"


def test_ftp_and_ldap_panels_carry_the_picker_too(qtbot: QtBot, tmp_path: Path) -> None:
    profile = _profile(tmp_path, _cred())
    ftp = FtpPanel()
    qtbot.addWidget(ftp)
    ftp.set_profile(profile)
    ldap = LdapPanel()
    qtbot.addWidget(ldap)
    ldap.set_profile(profile)

    ftp_seen: list[object] = []
    ftp.recon_requested.connect(lambda _m, _p, auth: ftp_seen.append(auth))
    ldap_seen: list[object] = []
    ldap.recon_requested.connect(lambda _b, _p, auth: ldap_seen.append(auth))

    ftp._auth._combo.setCurrentIndex(1)
    ftp._full.click()
    ldap._auth._combo.setCurrentIndex(1)
    ldap._recon.click()

    assert isinstance(ftp_seen[0], ReconAuth) and ftp_seen[0].username == "svc_account"
    assert isinstance(ldap_seen[0], ReconAuth) and ldap_seen[0].username == "svc_account"


def test_a_credential_added_later_reaches_the_picker(qtbot: QtBot, tmp_path: Path) -> None:
    # the whole point: http enum yields a password -> the SMB panel can use it without a restart
    profile = _profile(tmp_path)
    panel = SmbPanel()
    qtbot.addWidget(panel)
    panel.set_profile(profile)
    assert not panel._auth.has_credentials()

    profile.add_credential(_cred())
    panel.refresh_credentials()

    assert panel._auth.has_credentials()


def test_a_rotated_secret_keeps_the_selected_user(qtbot: QtBot) -> None:
    # editing a credential must not silently revert the next run to anonymous
    picker = AuthPicker()
    qtbot.addWidget(picker)
    picker.set_credentials([_cred()])
    picker._combo.setCurrentIndex(1)
    picker.set_credentials([_cred(secret="NewPassw0rd!")])
    auth = picker.current_auth()
    assert auth is not None and auth.secret == "NewPassw0rd!"


def test_a_service_with_no_authenticated_pass_shows_no_picker(qtbot: QtBot, tmp_path: Path) -> None:
    from oscprecon.gui.simple_recon import SIMPLE_SPECS
    from oscprecon.gui.widgets.simple_recon_panel import SimpleReconPanel

    ntp = SimpleReconPanel(SIMPLE_SPECS["ntp"])
    qtbot.addWidget(ntp)
    ntp.set_profile(_profile(tmp_path, _cred()))
    assert ntp._auth is None
    assert ntp.selected_auth() is None


def test_a_simple_panel_that_has_one_emits_it(qtbot: QtBot, tmp_path: Path) -> None:
    from oscprecon.gui.simple_recon import SIMPLE_SPECS
    from oscprecon.gui.widgets.simple_recon_panel import SimpleReconPanel

    winrm = SimpleReconPanel(SIMPLE_SPECS["winrm"])
    qtbot.addWidget(winrm)
    winrm.set_profile(_profile(tmp_path, _cred()))
    assert winrm._auth is not None
    seen: list[tuple[str, int, object]] = []
    winrm.recon_requested.connect(lambda m, p, a: seen.append((m, p, a)))

    winrm._auth._combo.setCurrentIndex(1)
    winrm._recon.click()

    assert seen[0][0] == "winrm"
    auth = seen[0][2]
    assert isinstance(auth, ReconAuth) and auth.username == "svc_account"
    assert "svc_account" in winrm._recon.text()


def test_the_tier2_followups_fill_from_the_picked_identity(qtbot: QtBot, tmp_path: Path) -> None:
    # otherwise "Run full SMB recon as svc_account" sits above Tier-2 commands pre-filled with a
    # different account — the operator runs one and wonders why it behaves differently
    profile = _profile(tmp_path, _cred("administrator", "AdminPw1"), _cred())
    panel = SmbPanel()
    qtbot.addWidget(panel)
    panel.set_profile(profile)

    def filled() -> str:
        return "\n".join(panel._manual.item(i).text() for i in range(panel._manual.count()))

    assert "administrator" in filled()  # the fallback: first usable password credential
    panel._auth._combo.setCurrentIndex(3)  # anonymous, guest, administrator, svc_account
    assert "svc_account" in filled()
    assert "Ticketmaster1968" in filled()  # §6: shown in full, never redacted
