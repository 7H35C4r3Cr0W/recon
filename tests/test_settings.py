import os
from pathlib import Path

from oscprecon import config


def test_defaults_when_prefs_empty() -> None:
    config.save_prefs({})
    loaded = config.load_settings()
    defaults = config.default_settings()
    assert loaded == defaults
    assert loaded.theme == "light"
    assert loaded.font_size == 0
    assert loaded.max_concurrency == config.DEFAULT_MAX_CONCURRENCY
    assert loaded.nmap_udp_full is False


def test_save_load_roundtrip() -> None:
    settings = config.Settings(
        workspace_root="/tmp/ws",
        wordlist_paths=["/a", "/b"],
        theme="dark",
        font_size=14,
        max_concurrency=8,
        nmap_udp_full=True,
    )
    config.save_settings(settings)
    assert config.load_settings() == settings.normalized()


def test_corrupt_values_fall_back_safely() -> None:
    config.save_prefs(
        {
            "font_size": "abc",
            "max_concurrency": "not-a-number",
            "theme": "pink",
            "nmap_udp_full": "maybe",
            "wordlist_paths": "",
        }
    )
    loaded = config.load_settings()
    assert loaded.font_size == 0  # unparseable → default (no override)
    assert loaded.max_concurrency == config.DEFAULT_MAX_CONCURRENCY
    assert loaded.theme == "light"  # unknown theme → default
    assert loaded.nmap_udp_full is False  # unknown bool → default
    assert loaded.wordlist_paths == config.default_settings().wordlist_paths


def test_out_of_range_values_are_clamped() -> None:
    config.save_prefs({"max_concurrency": "999", "font_size": "500"})
    loaded = config.load_settings()
    assert loaded.max_concurrency == config.CONCURRENCY_RANGE[1]
    assert loaded.font_size == config.FONT_SIZE_RANGE[1]


def test_clamp_on_save() -> None:
    config.save_settings(
        config.Settings(
            workspace_root="/tmp/ws",
            wordlist_paths=[],
            theme="dark",
            font_size=3,  # non-zero but below the min → clamps up
            max_concurrency=0,  # below min → clamps up
            nmap_udp_full=False,
        )
    )
    loaded = config.load_settings()
    assert loaded.font_size == config.FONT_SIZE_RANGE[0]
    assert loaded.max_concurrency == config.CONCURRENCY_RANGE[0]


def test_empty_workspace_root_falls_back_to_default() -> None:
    normalized = config.Settings(
        workspace_root="   ",
        wordlist_paths=[],
        theme="light",
        font_size=0,
        max_concurrency=4,
        nmap_udp_full=False,
    ).normalized()
    assert normalized.workspace_root == str(config.DEFAULT_WORKSPACE)


def test_wordlist_paths_pathsep_roundtrip() -> None:
    paths = ["/usr/share/seclists", "/home/user/wl"]
    config.save_settings(
        config.Settings(
            workspace_root="/tmp/ws",
            wordlist_paths=paths,
            theme="light",
            font_size=0,
            max_concurrency=4,
            nmap_udp_full=False,
        )
    )
    raw = config.load_prefs()["wordlist_paths"]
    assert raw == os.pathsep.join(paths)  # stored as a single pathsep string
    assert config.load_settings().wordlist_paths == paths


def test_save_preserves_unrelated_keys() -> None:
    config.save_prefs({"some_other_key": "keep-me"})
    config.save_settings(config.default_settings())
    assert config.load_prefs()["some_other_key"] == "keep-me"


def test_reset_restores_defaults_but_keeps_unrelated() -> None:
    config.save_prefs({"unrelated": "x"})
    config.save_settings(
        config.Settings(
            workspace_root="/tmp/other",
            wordlist_paths=["/z"],
            theme="dark",
            font_size=20,
            max_concurrency=12,
            nmap_udp_full=True,
        )
    )
    config.reset_settings()
    loaded = config.load_settings()
    assert loaded == config.default_settings()
    assert config.load_prefs()["unrelated"] == "x"


def test_settings_prefs_hold_only_known_non_secret_keys() -> None:
    keys = set(config.default_settings().to_prefs())
    assert keys == {
        "workspace_root",
        "wordlist_paths",
        "theme",
        "font_size",
        "max_concurrency",
        "nmap_udp_full",
    }


def test_credential_wordlists_stay_filtered_when_a_settings_path_is_added(tmp_path: Path) -> None:
    # the Preferences → Privacy tab promises password wordlists stay filtered; adding a Passwords/
    # tree via the new user-editable wordlist paths must NOT bypass that engine-level guarantee.
    # NOTE: the added root must NOT contain "password"/"passwd" in its path — is_excluded matches on
    # every path part, so a tmp dir named after this test would filter *everything* (incl. the
    # positive control below). Nest under a clean subdir and keep this function name secret-free.
    from oscprecon import wordlists

    wl_root = tmp_path / "seclists"
    (wl_root / "Discovery" / "Web-Content").mkdir(parents=True)
    (wl_root / "Passwords").mkdir(parents=True)
    (wl_root / "Discovery" / "Web-Content" / "common.txt").write_text("a\nb\n")
    (wl_root / "Passwords" / "rockyou.txt").write_text("secret\n")
    config.save_settings(
        config.Settings(
            workspace_root="/tmp/ws",
            wordlist_paths=[str(wl_root)],
            theme="light",
            font_size=0,
            max_concurrency=4,
            nmap_udp_full=False,
        )
    )
    names = [w.path.name for w in wordlists.index_wordlists()]
    assert "common.txt" in names  # positive control: the added path is really scanned
    assert "rockyou.txt" not in names  # password list never surfaced


def test_workspace_root_accessor_reflects_settings(tmp_path: Path) -> None:
    config.save_settings(
        config.Settings(
            workspace_root=str(tmp_path / "custom"),
            wordlist_paths=[],
            theme="light",
            font_size=0,
            max_concurrency=4,
            nmap_udp_full=False,
        )
    )
    assert config.workspace_root() == tmp_path / "custom"
