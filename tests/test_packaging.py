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
    assert has("oscprecon/gui/graph_html/index.html")
    assert has("oscprecon/gui/graph_html/cytoscape.min.js")
    assert len([n for n in names if n.endswith("manual_commands.yaml")]) >= 14
    assert len([n for n in names if "/patterns/" in n and n.endswith(".yaml")]) >= 10
    assert len([n for n in names if "/templates/" in n and not n.endswith("/")]) >= 1
