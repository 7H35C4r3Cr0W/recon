import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
# why: force the reference pane's link-label fallback so tests never spin up Chromium/QtWebEngine.
os.environ.setdefault("OSCPRECON_DISABLE_WEBVIEW", "1")


@pytest.fixture(autouse=True)
def _neuter_blocking_dialogs(monkeypatch: pytest.MonkeyPatch) -> None:
    # why: a modal dialog (QMessageBox/QFileDialog/QInputDialog/QDialog.exec) BLOCKS forever in the
    # offscreen headless test env — a single stray modal hangs the WHOLE suite (as _on_scan_preset's
    # "no project loaded" QMessageBox did: a deterministic ~16% hang that looked flaky). Auto-answer
    # them all, so a path that unexpectedly pops a modal becomes a fast, debuggable test FAILURE
    # instead of a hang. A test needing a specific return still overrides these with its own
    # monkeypatch (applied after this autouse fixture, so it wins).
    try:
        from PySide6.QtWidgets import QDialog, QFileDialog, QInputDialog, QMessageBox
    except Exception:  # pragma: no cover - non-GUI test runs without PySide6 loaded
        return
    ok = QMessageBox.StandardButton.Ok
    yes = QMessageBox.StandardButton.Yes
    for name in ("information", "warning", "critical", "about"):
        monkeypatch.setattr(QMessageBox, name, staticmethod(lambda *a, **k: ok))
    monkeypatch.setattr(QMessageBox, "question", staticmethod(lambda *a, **k: yes))
    monkeypatch.setattr(QFileDialog, "getOpenFileName", staticmethod(lambda *a, **k: ("", "")))
    monkeypatch.setattr(QFileDialog, "getSaveFileName", staticmethod(lambda *a, **k: ("", "")))
    monkeypatch.setattr(QFileDialog, "getExistingDirectory", staticmethod(lambda *a, **k: ""))
    monkeypatch.setattr(QInputDialog, "getText", staticmethod(lambda *a, **k: ("", False)))
    monkeypatch.setattr(QInputDialog, "getInt", staticmethod(lambda *a, **k: (0, False)))
    monkeypatch.setattr(QInputDialog, "getItem", staticmethod(lambda *a, **k: ("", False)))
    monkeypatch.setattr(QDialog, "exec", lambda self, *a, **k: 0)


@pytest.fixture(autouse=True)
def _isolate_oscprecon_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # why: keep tests from reading/writing the real ~/.config/oscprecon (recent.json etc.),
    # so GUI startup restore is deterministic and never touches the user's state. Also point the
    # workspace root at an empty tmp dir so the workspace dashboard scan never reads real profiles.
    # XDG_STATE_HOME keeps the diagnostics log (config.state_dir) out of the real ~/.local/state.
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    from oscprecon import config

    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    config.save_prefs({"workspace_root": str(workspace)})
