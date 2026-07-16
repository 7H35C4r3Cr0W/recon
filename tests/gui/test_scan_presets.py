import shlex
from pathlib import Path

import pytest
from pytestqt.qtbot import QtBot

from oscprecon import config, shell
from oscprecon.gui.main_window import _SCAN_PRESETS, MainWindow
from oscprecon.manual_commands import expand, load_manual_commands
from oscprecon.models import Target
from oscprecon.profile import Profile


def test_scan_presets_are_nmap_only_and_policy_clean() -> None:
    presets = load_manual_commands(_SCAN_PRESETS)
    assert len(presets) >= 8
    for p in presets:
        assert p.description and p.command and p.why
        filled = expand(p.command, target="10.10.10.5")
        argv = shlex.split(filled)
        assert argv[0] == "nmap"  # presets are nmap-only
        assert shell.policy_violation(argv) is None  # every preset passes the §2 policy


def test_scan_preset_prefills_command_builder(qtbot: QtBot, tmp_path: Path) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    window._set_profile(Profile.create(tmp_path, "b", Target(ip="10.10.10.42")))
    window._on_scan_preset("nmap -p- -Pn {target}")
    # target filled, dropped into the generic builder, generic page shown — NOT auto-run
    assert window._tool_panel._command.text() == "nmap -p- -Pn 10.10.10.42"
    assert window._tool_panel._stack.currentIndex() == 0
    assert window._tasks.active_count == 0  # nothing launched


def test_scan_preset_noop_without_profile(qtbot: QtBot) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    window._on_scan_preset("nmap -p- {target}")  # no profile -> must not raise
    assert window._tool_panel._command.text() == ""


def test_start_recon_passes_the_chosen_profile(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config.save_prefs({"preflight_ping": "false"})  # skip the pre-flight ping -> scan launches now
    window = MainWindow()
    qtbot.addWidget(window)
    window._set_profile(Profile.create(tmp_path, "b", Target(ip="10.10.10.42")))
    captured: dict[str, object] = {}
    monkeypatch.setattr(window, "_start", lambda worker, *a, **k: captured.update(worker=worker))
    window._start_recon("exam")
    assert captured["worker"]._scan_profile == "exam"  # type: ignore[attr-defined]


def test_start_recon_default_uses_the_configured_profile(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config.save_prefs({"scan_profile": "quick", "preflight_ping": "false"})
    window = MainWindow()
    qtbot.addWidget(window)
    window._set_profile(Profile.create(tmp_path, "b", Target(ip="10.10.10.42")))
    captured: dict[str, object] = {}
    monkeypatch.setattr(window, "_start", lambda worker, *a, **k: captured.update(worker=worker))
    window._start_recon(None)  # None -> fall back to the saved default
    assert captured["worker"]._scan_profile == "quick"  # type: ignore[attr-defined]
