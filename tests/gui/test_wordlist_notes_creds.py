from pathlib import Path

from pytestqt.qtbot import QtBot

from oscprecon import wordlists
from oscprecon.gui.main_window import AddCredentialDialog
from oscprecon.gui.widgets.notes_pane import NotesPane
from oscprecon.gui.widgets.wordlist_picker import WordlistPicker
from oscprecon.models import Target
from oscprecon.profile import Profile


def _tree(root: Path) -> None:
    (root / "Web-Content").mkdir()
    (root / "DNS").mkdir()
    (root / "Passwords").mkdir()
    (root / "Web-Content" / "common.txt").write_text("a\nb\nc\n")
    (root / "DNS" / "subs.txt").write_text("www\nmail\n")
    (root / "Passwords" / "top.txt").write_text("123\n")


def test_wordlist_picker_indexes_filters_favorites(qtbot: QtBot, tmp_path: Path) -> None:
    _tree(tmp_path)
    picker = WordlistPicker(paths=[tmp_path])
    qtbot.addWidget(picker)
    qtbot.waitUntil(lambda: picker._list.count() >= 2, timeout=5000)

    names = [picker._list.item(i).text() for i in range(picker._list.count())]
    assert any("common.txt" in name for name in names)
    assert not any("top.txt" in name for name in names)  # password list filtered

    picker._search.setText("common")
    assert picker._list.count() == 1

    picker._search.setText("")
    picker._list.setCurrentRow(picker._list.count() - 1)
    path = picker.selected_path()
    assert path is not None
    picker._toggle_favorite()
    assert wordlists.is_favorite(path)
    assert picker._list.item(0).text().startswith("★")  # favorite pinned to top


def test_notes_pane_autosaves_and_switches(qtbot: QtBot, tmp_path: Path) -> None:
    p1 = Profile.create(tmp_path, "box1", Target(ip="10.0.0.1"))
    p2 = Profile.create(tmp_path, "box2", Target(ip="10.0.0.2"))
    pane = NotesPane()
    qtbot.addWidget(pane)

    pane.set_profile(p1)
    pane._editor.setPlainText("findings for box1")
    pane.flush()
    assert "findings for box1" in p1.notes_path.read_text(encoding="utf-8")

    pane.set_profile(p2)  # flushes p1, loads p2's notes
    assert "findings for box1" not in pane._editor.toPlainText()


def test_add_credential_dialog(qtbot: QtBot) -> None:
    dialog = AddCredentialDialog()
    qtbot.addWidget(dialog)
    assert dialog.credential() is None  # username + secret required

    dialog._username.setText("svc")
    dialog._secret.setText("Sup3r")
    dialog._source.setText("smb-share")
    cred = dialog.credential()
    assert cred is not None
    assert cred.username == "svc"
    assert cred.secret == "Sup3r"
    assert cred.source == "smb-share"


def test_notes_pane_readonly_does_not_clobber_notes(qtbot: QtBot, tmp_path: Path) -> None:
    # regression: a read-only window's flush()/_save() (fired on set/clear_profile) must NOT write
    # notes.md — else it overwrites the writable window's newer notes with stale editor content.
    prof = Profile.create(tmp_path, "box", Target(ip="10.0.0.1"))
    prof.notes_path.write_text("NEWER notes from the writable window", encoding="utf-8")
    prof.read_only = True

    pane = NotesPane()
    qtbot.addWidget(pane)
    pane.set_profile(prof)  # loads the newer notes into the disabled editor
    pane._editor.setPlainText("STALE content")  # a divergent edit that must NOT be persisted
    pane.flush()
    assert prof.notes_path.read_text(encoding="utf-8") == "NEWER notes from the writable window"

    pane.clear_profile()  # also flushes — must still not write
    assert prof.notes_path.read_text(encoding="utf-8") == "NEWER notes from the writable window"
