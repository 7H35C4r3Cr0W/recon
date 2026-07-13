from pathlib import Path

import pytest
from PySide6.QtWidgets import QCheckBox, QLineEdit, QMessageBox
from pytestqt.qtbot import QtBot

from oscprecon import config
from oscprecon.gui.dialogs.settings import SettingsDialog


def _make(qtbot: QtBot, settings: config.Settings) -> SettingsDialog:
    dialog = SettingsDialog(settings)
    qtbot.addWidget(dialog)
    return dialog


def test_populate_reflects_settings(qtbot: QtBot) -> None:
    settings = config.Settings(
        workspace_root="/tmp/ws",
        wordlist_paths=["/a", "/b"],
        theme="dark",
        font_size=16,
        max_concurrency=9,
        nmap_udp_full=True,
    )
    d = _make(qtbot, settings)
    assert d._workspace_edit.text() == "/tmp/ws"
    assert d._theme_combo.currentData() == "dark"
    assert d._font_override.isChecked() and d._font_size.value() == 16
    assert d._concurrency.value() == 9
    assert d._udp_full.isChecked()
    assert [d._wordlist_list.item(i).text() for i in range(d._wordlist_list.count())] == [
        "/a",
        "/b",
    ]


def test_scan_profile_combo_populates_and_collects(qtbot: QtBot) -> None:
    settings = config.Settings(
        workspace_root="/tmp/ws",
        wordlist_paths=[],
        theme="light",
        font_size=0,
        max_concurrency=4,
        nmap_udp_full=False,
        scan_profile="exam",
    )
    d = _make(qtbot, settings)
    assert d._scan_profile.currentData() == "exam"  # populated from settings
    d._scan_profile.setCurrentIndex(d._scan_profile.findData("quick"))
    assert d.selected_settings().scan_profile == "quick"  # collected back out


def test_spray_toggle_populates_and_collects(qtbot: QtBot) -> None:
    settings = config.Settings(
        workspace_root="/tmp/ws",
        wordlist_paths=[],
        theme="light",
        font_size=0,
        max_concurrency=4,
        nmap_udp_full=False,
        spray_enabled=True,
    )
    d = _make(qtbot, settings)
    assert d._spray_enabled.isChecked()  # reflects the setting
    d._spray_enabled.setChecked(False)
    assert d.selected_settings().spray_enabled is False  # collected back out
    # default settings keep it OFF
    assert not _make(qtbot, config.default_settings())._spray_enabled.isChecked()


def test_eight_sections_present(qtbot: QtBot) -> None:
    d = _make(qtbot, config.default_settings())
    labels = [d._tabs.tabText(i) for i in range(d._tabs.count())]
    assert labels == [
        "Workspace",
        "Appearance",
        "Tool paths",
        "Scan",
        "Reports",
        "Privacy",
        "Performance",
        "Advanced",
    ]


def test_privacy_protections_are_locked_on(qtbot: QtBot) -> None:
    d = _make(qtbot, config.default_settings())
    privacy = d._tabs.widget(5)
    boxes = privacy.findChildren(QCheckBox)
    assert boxes  # protections are present
    for box in boxes:
        assert box.isChecked() and not box.isEnabled()  # cannot be switched off


def test_reports_tab_has_no_editable_controls(qtbot: QtBot) -> None:
    d = _make(qtbot, config.default_settings())
    reports = d._tabs.widget(4)
    # informational only: no toggles/inputs that could disable redaction or archiving
    assert not reports.findChildren(QCheckBox)
    assert not reports.findChildren(QLineEdit)


def test_font_override_toggles_spinbox(qtbot: QtBot) -> None:
    d = _make(qtbot, config.default_settings())
    assert not d._font_override.isChecked()
    assert not d._font_size.isEnabled()
    d._font_override.setChecked(True)
    assert d._font_size.isEnabled()


def test_add_and_remove_wordlist_path_dedups(qtbot: QtBot) -> None:
    d = _make(qtbot, config.default_settings())
    d._wordlist_list.clear()
    d.add_wordlist_path("/x")
    d.add_wordlist_path("/x")  # duplicate ignored
    assert d._wordlist_list.count() == 1
    d._wordlist_list.setCurrentRow(0)
    d._remove_wordlist_path()
    assert d._wordlist_list.count() == 0


def test_restore_defaults_repopulates_widgets(qtbot: QtBot) -> None:
    d = _make(qtbot, config.default_settings())
    d._theme_combo.setCurrentIndex(d._theme_combo.findData("dark"))
    d._concurrency.setValue(15)
    d._restore_defaults()
    assert d._theme_combo.currentData() == "light"
    assert d._concurrency.value() == config.DEFAULT_MAX_CONCURRENCY


def test_accept_saves_and_emits_applied(qtbot: QtBot, tmp_path: Path) -> None:
    settings = config.Settings(
        workspace_root=str(tmp_path),  # exists → no create prompt
        wordlist_paths=["/a"],
        theme="dark",
        font_size=18,
        max_concurrency=7,
        nmap_udp_full=True,
    )
    d = _make(qtbot, settings)
    with qtbot.waitSignal(d.applied) as blocker:
        d._on_accept()
    emitted = blocker.args[0]
    assert isinstance(emitted, config.Settings) and emitted.max_concurrency == 7
    reloaded = config.load_settings()
    assert reloaded.theme == "dark" and reloaded.nmap_udp_full is True


def test_accept_offers_to_create_missing_workspace(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "new-ws"
    d = _make(qtbot, config.default_settings())
    d._workspace_edit.setText(str(target))
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)
    with qtbot.waitSignal(d.applied):
        d._on_accept()
    assert target.is_dir()  # created on confirm


def test_accept_declined_create_does_not_save(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "unwanted-ws"
    d = _make(qtbot, config.default_settings())
    d._workspace_edit.setText(str(target))
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.No)
    triggered = []
    d.applied.connect(lambda s: triggered.append(s))
    d._on_accept()
    assert not target.exists() and not triggered  # nothing created, nothing saved


def test_mainwindow_apply_settings_updates_concurrency_and_theme_menu(qtbot: QtBot) -> None:
    from oscprecon.gui.main_window import MainWindow

    window = MainWindow()
    qtbot.addWidget(window)
    new = config.Settings(
        workspace_root=str(config.workspace_root()),
        wordlist_paths=[],
        theme="dark",
        font_size=0,
        max_concurrency=11,
        nmap_udp_full=False,
    )
    window._apply_settings(new)
    assert window._tasks.max_concurrency == 11
    checked = [a.text().lower() for a in window._theme_group.actions() if a.isChecked()]
    assert checked == ["dark"]
