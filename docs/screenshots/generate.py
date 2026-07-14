#!/usr/bin/env python
"""Regenerate the Nabu screenshot set from GENERATED data only (no real targets/credentials).

    QT_QPA_PLATFORM=offscreen uv run python docs/screenshots/generate.py

Renders widgets off-screen and saves PNGs next to this file. Deterministic, offline, no network.
The graph/HackTricks-live panes need Chromium (QtWebEngine) and are skipped here — the offline
reference render is captured instead. Secrets are always masked (length only), same as the live UI.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("OSCPRECON_DISABLE_WEBVIEW", "1")

from PySide6.QtWidgets import QApplication, QWidget  # noqa: E402

from oscprecon import audit  # noqa: E402
from oscprecon import findings as findings_mod  # noqa: E402
from oscprecon.gui import theme  # noqa: E402
from oscprecon.gui.dialogs.cred_vault import CredentialVaultDialog  # noqa: E402
from oscprecon.gui.dialogs.new_profile import NewProfileDialog  # noqa: E402
from oscprecon.gui.dialogs.spray import SprayDialog  # noqa: E402
from oscprecon.gui.main_window import MainWindow  # noqa: E402
from oscprecon.gui.widgets.activity_view import ActivityView  # noqa: E402
from oscprecon.gui.widgets.findings_view import FindingsView  # noqa: E402
from oscprecon.gui.widgets.http_panel import HttpPanel  # noqa: E402
from oscprecon.gui.widgets.reference_pane import ReferencePane  # noqa: E402
from oscprecon.gui.widgets.smb_panel import SmbPanel  # noqa: E402
from oscprecon.models import Credential, DiscoveredService, Proto, Target  # noqa: E402
from oscprecon.profile import Profile  # noqa: E402
from oscprecon.references import ServiceRef  # noqa: E402

OUT = Path(__file__).parent
_SMB_URL = "https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-smb/index.html"


def _demo_profile(root: Path) -> Profile:
    prof = Profile.create(root, "demo-box", Target(ip="10.10.10.100", hostname="demo.local"))
    prof.set_services(
        [
            DiscoveredService(22, Proto.TCP, "ssh", "OpenSSH", "8.4p1"),
            DiscoveredService(80, Proto.TCP, "http", "nginx", "1.18"),
            DiscoveredService(445, Proto.TCP, "microsoft-ds", "Windows Server 2019", ""),
            DiscoveredService(161, Proto.UDP, "snmp", "", ""),
        ]
    )
    findings_mod.add_findings(
        prof.directory,
        [
            {
                "module": "smb",
                "kind": "signing",
                "value": "disabled",
                "detail": "SMB2 message signing not required",
                "discovered_at": "t",
            },
            {
                "module": "ftp",
                "kind": "auth",
                "value": "anonymous",
                "detail": "anonymous login allowed",
                "discovered_at": "t",
            },
            {
                "module": "ssh",
                "kind": "product",
                "value": "OpenSSH 8.4p1",
                "detail": "Ubuntu",
                "discovered_at": "t",
            },
            {
                "module": "ssh",
                "kind": "edb",
                "value": "EDB-45210",
                "detail": "OpenSSH 2.3 < 7.7 user enumeration",
                "discovered_at": "t",
            },
            {
                "module": "nfs",
                "kind": "world-readable",
                "value": "/srv/backups",
                "detail": "no_root_squash",
                "discovered_at": "t",
            },
        ],
    )
    prof.add_credential(
        Credential(
            username="svc_backup",
            secret="not-a-real-secret",
            domain="demo.local",
            source="smb-share-readme",
            tested_against=["spray-confirmed:smb"],
        )
    )
    return prof


def _save(widget: QWidget, name: str, size: tuple[int, int]) -> None:
    widget.resize(*size)
    widget.grab().save(str(OUT / name))
    print("wrote", name)


def main() -> int:
    QApplication([])  # Qt holds the singleton; no local ref needed
    tmp = Path(tempfile.mkdtemp())

    for name in ("light", "dark"):
        theme.apply_theme(name)
        window = MainWindow()
        window._set_profile(_demo_profile(tmp / name))
        window._restyle_shell(name)
        window._tool_panel.append_output("[done] nmap: 4 services discovered")
        _save(window, f"shell-{name}.png", (1180, 720))
        window._dashboard.shutdown()
    theme.apply_theme("light")

    empty = MainWindow()
    empty._show_workspace()
    _save(empty, "dashboard-empty.png", (1180, 720))
    empty._dashboard.shutdown()

    prof = _demo_profile(tmp / "views")
    fv = FindingsView("light")  # match the light Qt palette applied above
    fv.set_profile(prof)
    _save(fv, "findings.png", (820, 360))

    vault = CredentialVaultDialog(prof)
    vault._table.selectRow(0)
    _save(vault, "credential-vault.png", (700, 360))

    smb = SmbPanel()
    smb.set_profile(prof)
    smb.configure(DiscoveredService(445, Proto.TCP, "microsoft-ds"))
    _save(smb, "smb-tool-panel.png", (600, 440))

    ref = ReferencePane("light")
    ref.show_service(
        DiscoveredService(445, Proto.TCP, "microsoft-ds", "Samba", "4.9"),
        ServiceRef(label="SMB", hacktricks=_SMB_URL, module="smb", tools=[]),
        [{"module": "smb", "kind": "auth", "value": "null session"}],
    )
    _save(ref, "reference-offline.png", (400, 620))

    dlg = NewProfileDialog()
    dlg._name.setText("htb-active")
    dlg._ip.setText("10.10.10.100")
    _save(dlg, "new-project.png", (440, 220))

    http = HttpPanel()
    http.set_profile(prof)
    http.configure(
        DiscoveredService(80, Proto.TCP, "http", "nginx", "1.18"),
        ServiceRef(label="HTTP", hacktricks="", module="http", tools=[]),
    )
    _save(http, "http-panel.png", (620, 560))

    spray = SprayDialog(prof, spray_enabled=True)
    for key in ("smb", "ftp"):
        if key in spray._checks:
            spray._checks[key].setChecked(True)
    _save(spray, "spray-dialog.png", (620, 460))

    audit.record(prof.directory, prof.profile_name, "run-command", details={"module": "nmap"})
    audit.record(prof.directory, prof.profile_name, "credential-added", details={"source": "smb"})
    audit.record(prof.directory, prof.profile_name, "reference-visited", details={"service": "smb"})
    act = ActivityView("light")
    act.set_profile(prof)
    _save(act, "activity.png", (820, 300))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
