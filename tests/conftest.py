import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(autouse=True)
def _isolate_oscprecon_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # why: keep tests from reading/writing the real ~/.config/oscprecon (recent.json etc.),
    # so GUI startup restore is deterministic and never touches the user's state.
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
