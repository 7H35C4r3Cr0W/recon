from pathlib import Path

import pytest

from oscprecon import config


def test_prefs_roundtrip_atomic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    config.save_prefs({"workspace_root": "/x", "theme": "dark"})
    assert config.load_prefs() == {"workspace_root": "/x", "theme": "dark"}
    # atomic temp+rename leaves no stray .tmp behind
    assert not list((tmp_path / "oscprecon").glob("*.tmp"))


def test_recent_roundtrip_atomic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    config.add_recent(tmp_path / "a")
    config.add_recent(tmp_path / "b")
    recent = config.recent_profiles()
    assert recent[0] == str((tmp_path / "b").resolve())  # most-recent first
    assert str((tmp_path / "a").resolve()) in recent
    assert not list((tmp_path / "oscprecon").glob("*.tmp"))


def test_prefs_write_failure_preserves_existing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    config.save_prefs({"workspace_root": "/good"})

    def boom(self: Path, target: Path) -> None:  # simulate the atomic rename failing (disk full)
        raise OSError("disk full")

    monkeypatch.setattr(config.Path, "replace", boom)
    with pytest.raises(OSError):
        config.save_prefs({"workspace_root": "/bad"})
    monkeypatch.undo()
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    # the previous valid config survived the failed write (temp+rename never clobbered it)
    assert config.load_prefs() == {"workspace_root": "/good"}


def test_corrupt_config_falls_back_safely(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    cfg = tmp_path / "oscprecon"
    cfg.mkdir(parents=True, exist_ok=True)
    (cfg / "prefs.json").write_text("{ this is not json", encoding="utf-8")
    (cfg / "recent.json").write_text("]]not json[[", encoding="utf-8")
    assert config.load_prefs() == {}
    assert config.recent_profiles() == []


def test_recent_dedups_and_caps(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    for i in range(config.RECENT_LIMIT + 5):
        config.add_recent(tmp_path / f"p{i}")
    config.add_recent(tmp_path / "p0")  # re-adding moves it to front, not a duplicate
    recent = config.recent_profiles()
    assert len(recent) == config.RECENT_LIMIT
    assert recent[0] == str((tmp_path / "p0").resolve())
    assert len(recent) == len(set(recent))
