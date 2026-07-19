from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont, QGuiApplication
from PySide6.QtWidgets import (
    QButtonGroup,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from oscprecon import ligolo
from oscprecon.gui.theme import styles, tokens
from oscprecon.profile import Profile

# The Pivot tab. A guided, copy-paste command-builder for the ligolo-ng pivot workflow — Nabu never
# runs ligolo (it's a tunnelling relay, not a recon tool, and a tun/route needs root); it generates
# the exact commands for your values, the same "shown, you run it" model as the Tier-2 helpers. Once
# the internal /24 is routable over the ligolo interface, "Scan a host / range" scans it via the
# tunnel. Linux and Windows pivots need different agent delivery, so the OS is a first-class switch
# here. Docs: https://docs.ligolo.ng/ · Releases (grab the current binary): see the header.


class PivotPanel(QWidget):
    add_network_requested = Signal()  # host opens the "import a pivot scan" dialog
    scan_range_requested = Signal()  # host opens the custom-scan dialog (scan the internal /24)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._profile: Profile | None = None

        title = QLabel("Pivot — reach an internal network")
        title.setStyleSheet(
            f"font-size: 18px; font-weight: 700; color: {tokens.active_palette().text};"
        )

        intro = QLabel(
            "Tunnel from a compromised host into a network you otherwise can't route to, then scan "
            "it in Nabu. Fill in your values — the commands update live. Nabu doesn't run ligolo; "
            "copy each command and run it where the card says."
        )
        intro.setWordWrap(True)

        links = QLabel(
            f'<a href="{ligolo.LIGOLO_GITHUB}">GitHub</a> &nbsp;·&nbsp; '
            f'<a href="{ligolo.LIGOLO_RELEASES}">Latest release (download proxy + agent)</a> '
            f'&nbsp;·&nbsp; <a href="{ligolo.LIGOLO_DOCS}">Docs</a>'
        )
        links.setOpenExternalLinks(True)
        links.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)

        self._version_note = QLabel(
            f"ⓘ Syntax checked against ligolo-ng {ligolo.LIGOLO_REF_VERSION} "
            f"({ligolo.LIGOLO_REF_VERIFIED}). Ligolo-ng updates often — grab the current binary "
            "from the release link above and confirm the console verbs (older builds use "
            "<code>start</code> not <code>tunnel_start</code>, and auto-create the interface)."
        )
        self._version_note.setWordWrap(True)
        self._version_note.setStyleSheet(
            f"color: {tokens.active_palette().text_muted}; font-size: 11px;"
        )

        # --- inputs -------------------------------------------------------------------------------
        self._os_linux = QRadioButton("Linux pivot")
        self._os_windows = QRadioButton("Windows pivot")
        self._os_linux.setChecked(True)
        self._os_group = QButtonGroup(self)
        self._os_group.addButton(self._os_linux)
        self._os_group.addButton(self._os_windows)
        os_row = QHBoxLayout()
        os_row.addWidget(QLabel("Pivot host OS:"))
        os_row.addWidget(self._os_linux)
        os_row.addWidget(self._os_windows)
        os_row.addStretch(1)

        self._ip = QLineEdit(ligolo.detect_tun_ip("tun0"))
        self._ip.setPlaceholderText("your VPN/tun0 IP (the agent dials back to this)")
        self._port = QLineEdit("11601")
        self._iface = QLineEdit("ligolo")
        self._routes = QLineEdit()
        self._routes.setPlaceholderText(
            "internal /24(s), comma-separated — e.g. 172.16.1.0/24, 10.10.5.0/24"
        )
        form = QFormLayout()
        form.addRow("Attacker (tun0) IP:", self._ip)
        form.addRow("Proxy port:", self._port)
        form.addRow("Interface name:", self._iface)
        form.addRow("Internal route(s):", self._routes)

        # --- step cards (scroll) ------------------------------------------------------------------
        self._steps_host = QWidget()
        self._steps_layout = QVBoxLayout(self._steps_host)
        self._steps_layout.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(self._steps_host)

        # --- post-tunnel actions (moved here from the old header menu) ---------------------------
        import_btn = QPushButton("Import a pivot scan…")
        import_btn.setToolTip(
            "Paste/import an nmap run of the internal /24 done from the foothold — hosts stream "
            "into the recon tree + graph, grouped by subnet."
        )
        import_btn.clicked.connect(self.add_network_requested)
        scan_btn = QPushButton("Scan a host / range…")
        scan_btn.setStyleSheet(styles.accent_button())
        scan_btn.setToolTip(
            "Once the route is up, scan the internal host/range through the tunnel."
        )
        scan_btn.clicked.connect(self.scan_range_requested)
        actions = QHBoxLayout()
        actions.addWidget(QLabel("After the tunnel is up:"))
        actions.addWidget(import_btn)
        actions.addWidget(scan_btn)
        actions.addStretch(1)

        header = QVBoxLayout()
        header.setSpacing(tokens.SPACE_XS)
        header.addWidget(title)
        header.addWidget(intro)
        header.addWidget(links)
        header.addWidget(self._version_note)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(
            tokens.SPACE_MD, tokens.SPACE_MD, tokens.SPACE_MD, tokens.SPACE_MD
        )
        layout.addLayout(header)
        layout.addLayout(form)
        layout.addLayout(os_row)
        layout.addWidget(QLabel("Steps:"))
        layout.addWidget(scroll, stretch=1)
        layout.addLayout(actions)

        for widget in (self._ip, self._port, self._iface, self._routes):
            widget.textChanged.connect(self._rebuild)
        self._os_linux.toggled.connect(self._rebuild)
        self._rebuild()

    def set_profile(self, profile: Profile | None) -> None:
        self._profile = profile
        # seed the route(s) with subnets discovered on this project so the scan step is concrete
        if profile is not None and not self._routes.text().strip():
            subnets = sorted({h.subnet for h in profile.discovered_hosts if h.subnet})
            if subnets:
                self._routes.setText(", ".join(subnets))
        if not self._ip.text().strip():
            self._ip.setText(ligolo.detect_tun_ip("tun0"))
        self._rebuild()

    def _agent_os(self) -> str:
        return "windows" if self._os_windows.isChecked() else "linux"

    def _rebuild(self) -> None:
        while self._steps_layout.count():
            item = self._steps_layout.takeAt(0)
            widget = item.widget() if item is not None else None
            if widget is not None:
                widget.deleteLater()
        try:
            port = int(self._port.text().strip() or "11601")
        except ValueError:
            port = 11601
        routes = [r.strip() for r in self._routes.text().replace(";", ",").split(",") if r.strip()]
        steps = ligolo.build_ligolo_steps(
            self._ip.text().strip(),
            port=port,
            iface=self._iface.text().strip(),
            routes=routes,
            agent_os=self._agent_os(),
        )
        for step in steps:
            self._steps_layout.addWidget(self._step_card(step))
        self._steps_layout.addStretch(1)

    def _step_card(self, step: ligolo.LigoloStep) -> QWidget:
        pal = tokens.active_palette()
        card = QFrame()
        card.setFrameShape(QFrame.Shape.StyledPanel)
        card.setStyleSheet(
            f"QFrame {{ background: {pal.surface_alt}; border: 1px solid {pal.border};"
            f" border-radius: {tokens.RADIUS_SM}px; }}"
        )
        outer = QVBoxLayout(card)
        header = QLabel(f"<b>{step.n}. {step.title}</b>  —  <i>on {step.where}</i>")
        header.setWordWrap(True)
        outer.addWidget(header)

        cmd_text = "\n".join(step.commands)
        body = QPlainTextEdit(cmd_text)
        body.setReadOnly(True)
        body.setFont(QFont("monospace"))
        body.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        body.setFixedHeight(22 + 18 * max(1, len(step.commands)))
        row = QHBoxLayout()
        row.addWidget(body, stretch=1)
        copy = QPushButton("Copy")
        copy.clicked.connect(lambda _=False, text=cmd_text: self._copy(text))
        row.addWidget(copy, alignment=Qt.AlignmentFlag.AlignTop)
        outer.addLayout(row)

        if step.note:
            note = QLabel(step.note)
            note.setWordWrap(True)
            note.setStyleSheet(f"color: {pal.text_muted}; font-size: 11px;")
            outer.addWidget(note)
        return card

    @staticmethod
    def _copy(text: str) -> None:
        clip = QGuiApplication.clipboard()
        if clip is not None:
            clip.setText(text)
