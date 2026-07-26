from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QComboBox, QHBoxLayout, QLabel, QWidget

from oscprecon.models import Credential
from oscprecon.recon_auth import ReconAuth

# The "run this enumeration AS…" control. Every service panel that can authenticate carries one, so
# the credential you already found is one dropdown away from the recon that uses it — instead of
# being locked in the vault where only the Exploitation tab could see it.


class AuthPicker(QWidget):
    changed = Signal()

    def __init__(self, extra_anonymous: tuple[tuple[str, ReconAuth], ...] = ()) -> None:
        super().__init__()
        self._creds: list[Credential] = []
        self._extra = extra_anonymous
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        label = QLabel("Run as:")
        self._combo = QComboBox()
        self._combo.setAccessibleName("recon identity")
        self._combo.setToolTip(
            "Which identity to enumerate as.\n\n"
            "Anonymous is the first move. Pick a vault credential to re-run the same enumeration "
            "authenticated — that is what you do the moment http/ftp/a share hands you a password, "
            "and it returns far more.\n\n"
            "This is not a credential attack: it uses ONE credential you already hold."
        )
        self._hint = QLabel("")
        self._hint.setObjectName("authHint")
        layout.addWidget(label)
        layout.addWidget(self._combo, stretch=1)
        layout.addWidget(self._hint)
        self._combo.currentIndexChanged.connect(lambda _i: self._on_change())
        self.set_credentials([])

    def set_credentials(self, creds: list[Credential]) -> None:
        # keep the operator's choice across a vault refresh: they picked svc_account, a new
        # credential landing in the vault must not silently switch the run back to anonymous.
        previous = self.current_auth()
        self._creds = [c for c in creds if c.username and c.secret]
        self._combo.blockSignals(True)
        self._combo.clear()
        self._combo.addItem("anonymous / null session", None)
        for name, auth in self._extra:
            self._combo.addItem(name, auth)
        for cred in self._creds:
            who = f"{cred.domain}\\{cred.username}" if cred.domain else cred.username
            kind = "hash" if cred.secret_type == "hash" else "password"
            source = f" — {cred.source}" if cred.source else ""
            self._combo.addItem(f"{who}  ({kind}){source}", ReconAuth.from_credential(cred))
        restored = self._index_of(previous)
        self._combo.setCurrentIndex(restored)
        self._combo.blockSignals(False)
        self._update_hint()
        if self.current_auth() != previous:
            self.changed.emit()

    def _index_of(self, auth: ReconAuth | None) -> int:
        if auth is None or auth.anonymous:
            for i in range(self._combo.count()):
                if self._matches(self._combo.itemData(i), auth):
                    return i
            return 0
        for i in range(self._combo.count()):
            candidate = self._combo.itemData(i)
            if isinstance(candidate, ReconAuth) and candidate == auth:
                return i
        # the secret was rotated (or the domain filled in) — the operator still means that USER, so
        # keep the choice instead of silently reverting the next run to anonymous
        for i in range(self._combo.count()):
            candidate = self._combo.itemData(i)
            if isinstance(candidate, ReconAuth) and candidate.username == auth.username:
                return i
        return 0

    @staticmethod
    def _matches(candidate: object, auth: ReconAuth | None) -> bool:
        if auth is None:
            return candidate is None
        return isinstance(candidate, ReconAuth) and candidate == auth

    def current_auth(self) -> ReconAuth | None:
        data = self._combo.itemData(self._combo.currentIndex())
        return data if isinstance(data, ReconAuth) else None

    def has_credentials(self) -> bool:
        return bool(self._creds)

    def _on_change(self) -> None:
        self._update_hint()
        self.changed.emit()

    def _update_hint(self) -> None:
        # the hint carries what the combo text does NOT: where an authenticated run's output lands
        # (its own folder, so it can't overwrite the anonymous snapshot), or why the list is short.
        auth = self.current_auth()
        if auth is None or auth.anonymous:
            self._hint.setText(
                "" if self._creds else "no vault credentials yet — Edit → Add Credential"
            )
            return
        self._hint.setText(f"→ {auth.output_slug}/")
