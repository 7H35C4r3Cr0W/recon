from __future__ import annotations

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QLabel, QPlainTextEdit, QVBoxLayout, QWidget

from oscprecon.profile import Profile


class NotesPane(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self._profile: Profile | None = None
        self._loading = False

        self._editor = QPlainTextEdit()
        self._editor.setPlaceholderText("notes are saved to <profile>/notes.md")
        self._editor.textChanged.connect(self._on_changed)
        self._status = QLabel("No profile loaded.")

        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(800)
        self._timer.timeout.connect(self._save)

        layout = QVBoxLayout(self)
        layout.addWidget(self._editor, stretch=1)
        layout.addWidget(self._status)

    def set_profile(self, profile: Profile) -> None:
        # why: a no-op re-set with the same profile (fired on every background worker completion)
        # must not reload the editor — setPlainText resets cursor/scroll/undo while the user types.
        if profile is self._profile:
            return
        self.flush()
        self._profile = profile
        self._loading = True
        text = profile.notes_path.read_text(encoding="utf-8") if profile.notes_path.exists() else ""
        self._editor.setPlainText(text)
        self._loading = False
        self._status.setText(str(profile.notes_path))

    def clear_profile(self) -> None:
        self.flush()
        self._profile = None
        self._loading = True
        self._editor.setPlainText("")
        self._loading = False
        self._status.setText("No profile loaded.")

    def flush(self) -> None:
        self._timer.stop()
        self._save()

    def _on_changed(self) -> None:
        if self._loading or self._profile is None:
            return
        self._timer.start()

    def _save(self) -> None:
        if self._profile is None:
            return
        path = self._profile.notes_path
        # why: atomic write (temp+replace) — notes are the user's findings; don't lose them.
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(self._editor.toPlainText(), encoding="utf-8")
        tmp.replace(path)
        self._status.setText(f"saved · {path.name}")
