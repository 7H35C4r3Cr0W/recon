import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
# why: force the reference pane's link-label fallback so tests never spin up Chromium/QtWebEngine.
os.environ.setdefault("OSCPRECON_DISABLE_WEBVIEW", "1")


@pytest.fixture(autouse=True)
def _isolate_oscprecon_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # why: keep tests from reading/writing the real ~/.config/oscprecon (recent.json etc.),
    # so GUI startup restore is deterministic and never touches the user's state. Also point the
    # workspace root at an empty tmp dir so the workspace dashboard scan never reads real profiles.
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    from oscprecon import config

    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    config.save_prefs({"workspace_root": str(workspace)})
