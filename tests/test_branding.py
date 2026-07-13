import pathlib
from tomllib import loads

from oscprecon import branding

REPO = pathlib.Path(__file__).resolve().parents[1]


def test_display_name_is_nabu() -> None:
    assert branding.APP_NAME == "Nabu"
    # the display brand is separate from the install/dist name, which stays compatible
    assert branding.DIST_NAME == "oscp-recon"
    assert branding.app_version()  # resolves for installed or in-checkout runs


def test_entry_points_prefer_nabu_and_keep_legacy_aliases() -> None:
    scripts = loads((REPO / "pyproject.toml").read_text())["project"]["scripts"]
    # preferred Nabu entry points exist and point at the real callables
    assert scripts["nabu"] == "oscprecon.gui.app:main"
    assert scripts["nabu-cli"] == "oscprecon.cli:app"
    # legacy aliases are preserved so existing scripts/launchers keep working
    assert scripts["oscprecon-cli"] == "oscprecon.cli:app"
    assert scripts["oscprecon"] == "oscprecon.gui.app:main"
    assert scripts["oscp-recon"] == "oscprecon.__main__:main"


def test_internal_package_and_data_paths_are_unchanged() -> None:
    # branding must NOT move the package or the user's data — importable under the old name and
    # the default workspace root is still ~/oscprecon (no destructive migration).
    import oscprecon
    from oscprecon import config

    expected_workspace = pathlib.Path.home() / "oscprecon"
    assert oscprecon.__name__ == "oscprecon"
    assert config.APP_NAME == "oscprecon"  # XDG config dir stays ~/.config/oscprecon
    assert expected_workspace == config.DEFAULT_WORKSPACE
