import pathlib
import shutil
import subprocess
import zipfile

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
PKG = REPO / "src" / "oscprecon"


def test_runtime_resources_resolve_package_relative() -> None:
    # fast guard: every resource the engine loads at runtime is located relative to the package
    # (not cwd / repo root), so it still resolves when installed outside the checkout.
    assert (PKG / "references" / "services.yaml").exists()
    assert (PKG / "gui" / "graph_html" / "index.html").exists()
    assert (PKG / "gui" / "graph_html" / "cytoscape.min.js").exists()
    assert len(list((PKG / "patterns").glob("*.yaml"))) >= 10
    assert len(list((PKG / "templates").glob("*"))) >= 1
    assert len(list(PKG.glob("modules/*/manual_commands.yaml"))) >= 14
    # vendored HackTricks offline snapshot (index + per-service markdown)
    assert (PKG / "references" / "hacktricks" / "index.json").exists()
    assert len(list((PKG / "references" / "hacktricks" / "pages").glob("*.md"))) >= 18
    # workspace backend + dashboard GUI packages
    for module in ("index", "search", "health", "locks", "activity", "views", "bulk", "models"):
        assert (PKG / "workspace" / f"{module}.py").exists()
    assert (PKG / "gui" / "workspace" / "dashboard.py").exists()


@pytest.mark.skipif(shutil.which("uv") is None, reason="uv not on PATH")
def test_wheel_bundles_runtime_resources(tmp_path: pathlib.Path) -> None:
    # build a wheel and prove the non-.py resources are actually shipped (hatchling default
    # inclusion) — the failure class where a pip-installed app is missing its YAML/HTML/templates.
    subprocess.run(
        ["uv", "build", "--wheel", "--out-dir", str(tmp_path)],
        cwd=REPO,
        check=True,
        capture_output=True,
    )
    wheels = list(tmp_path.glob("*.whl"))
    assert wheels, "wheel build produced no artifact"
    names = zipfile.ZipFile(wheels[0]).namelist()

    def has(sub: str) -> bool:
        return any(sub in n for n in names)

    assert has("oscprecon/references/services.yaml")
    assert has("oscprecon/references/hacktricks/index.json")
    assert len([n for n in names if "/hacktricks/pages/" in n and n.endswith(".md")]) >= 18
    assert has("oscprecon/gui/graph_html/index.html")
    assert has("oscprecon/gui/graph_html/cytoscape.min.js")
    assert len([n for n in names if n.endswith("manual_commands.yaml")]) >= 14
    assert len([n for n in names if "/patterns/" in n and n.endswith(".yaml")]) >= 10
    assert len([n for n in names if "/templates/" in n and not n.endswith("/")]) >= 1


def test_appimage_packaging_assets_are_present_and_well_formed() -> None:
    # the single-click contained-app build (packaging/build-appimage.sh) is maintainer infra: it is
    # NOT shipped in the wheel, but its inputs must stay valid so a maintainer can build on Kali.
    pkg = REPO / "packaging"
    script = pkg / "build-appimage.sh"
    desktop = pkg / "nabu.desktop"
    icon = pkg / "nabu.png"
    assert script.exists() and desktop.exists() and icon.exists()

    icon_bytes = icon.read_bytes()
    assert icon_bytes[:8] == b"\x89PNG\r\n\x1a\n"  # valid PNG magic

    desktop_text = desktop.read_text()
    assert "[Desktop Entry]" in desktop_text
    assert "Name=Nabu" in desktop_text  # user-facing launcher identity is Nabu
    assert "Exec=nabu" in desktop_text
    assert "Icon=nabu" in desktop_text

    script_text = script.read_text()
    assert script_text.startswith("#!/usr/bin/env bash")
    # user-facing AppImage artifact carries the Nabu name
    assert "Nabu-${VERSION}" in script_text
    # runtime app must stay network-free; the AppImage entry runs the module, nothing forbidden
    assert "-m oscprecon" in script_text
    for forbidden in ("metasploit", "msfvenom", "sqlmap", "hydra", "curl http", "wget http"):
        assert forbidden not in script_text.lower()


def test_packaging_dir_is_not_shipped_in_the_wheel() -> None:
    # packaging/ is build infra — hatchling ships only src/oscprecon, so the wheel must not carry it
    from tomllib import loads

    cfg = loads((REPO / "pyproject.toml").read_text())
    assert cfg["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"] == ["src/oscprecon"]


def test_install_script_is_present_and_safe() -> None:
    # install.sh is the fresh-Kali bootstrap: it must be fail-safe and recon-only by default (spray
    # tools are opt-in), and it must never install/run anything forbidden.
    script = REPO / "install.sh"
    assert script.exists()
    text = script.read_text()
    assert text.startswith("#!/usr/bin/env bash")
    assert "set -euo pipefail" in text  # fail-safe

    core = text.split("CORE_PKGS=(", 1)[1].split(")", 1)[0]
    assert (
        "hydra" not in core and "medusa" not in core
    )  # spray tools are NOT in the default install
    assert "hydra medusa" in text  # they exist only behind --with-spray
    assert "--with-spray" in text
    for forbidden in ("metasploit", "msfvenom", "sqlmap", "nessus", "burpsuite"):
        assert forbidden not in text.lower()
    assert "uv sync" in text and "oscprecon-cli doctor" in text  # sets up + checks readiness
