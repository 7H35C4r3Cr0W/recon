import pytest
from PySide6.QtWidgets import QLabel
from pytestqt.qtbot import QtBot

from oscprecon import doctor
from oscprecon.gui.dialogs.doctor import DoctorDialog


def test_doctor_dialog_shows_status(qtbot: QtBot, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(doctor.shutil, "which", lambda t: "/usr/bin/nmap" if t == "nmap" else None)
    d = DoctorDialog()
    qtbot.addWidget(d)
    html = d._view.toHtml()
    assert "nmap" in html  # present, ticked
    assert "Missing" in html and "smbclient" in html  # missing tools listed with hints
    assert "apt install" in html  # install hint shown
    # a wholly-missing alternative group is shown once by its preferred member (netexec), never the
    # deprecated alias, so the user isn't nudged to install crackmapexec.
    assert "netexec" in html and "crackmapexec" not in html


def test_doctor_dialog_all_present(qtbot: QtBot, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(doctor.shutil, "which", lambda t: f"/usr/bin/{t}")
    d = DoctorDialog()
    qtbot.addWidget(d)
    assert "Missing" not in d._view.toHtml()  # nothing missing


def test_doctor_dialog_counts_alternatives_as_covered(
    qtbot: QtBot, monkeypatch: pytest.MonkeyPatch
) -> None:
    # netexec present but the nxc/crackmapexec aliases absent, everything else present: the box must
    # read exam-ready — interchangeable tools are NOT surfaced as gaps (was a misleading dialog).
    absent = {"nxc", "crackmapexec"}
    monkeypatch.setattr(doctor.shutil, "which", lambda t: None if t in absent else f"/usr/bin/{t}")
    d = DoctorDialog()
    qtbot.addWidget(d)
    assert "Missing" not in d._view.toHtml()
    assert "exam-ready" in d.findChildren(QLabel)[0].text()


def test_doctor_dialog_shows_spray_tools_section(
    qtbot: QtBot, monkeypatch: pytest.MonkeyPatch
) -> None:
    # medusa missing, everything else present -> exam-ready + a separate Spray-mode tools section
    monkeypatch.setattr(
        doctor.shutil, "which", lambda t: None if t == "medusa" else f"/usr/bin/{t}"
    )
    d = DoctorDialog()
    qtbot.addWidget(d)
    html = d._view.toHtml()
    assert "Spray-mode tools" in html and "medusa" in html
    assert "Missing" not in html  # required tools all present -> no required-Missing section
