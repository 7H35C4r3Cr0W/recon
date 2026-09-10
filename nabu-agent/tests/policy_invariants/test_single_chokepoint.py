"""INVARIANT: exactly one module executes tools; no home-grown exec path anywhere else.

Structural (AST) assertions over the whole ``nabu_agent`` package:
  * no ``subprocess`` / ``pty`` import, no ``os.system`` / ``os.popen`` / ``*.spawn``, no ``shell=True``;
  * ``shell.run(...)`` is called ONLY from ``engine/shell_gateway.py``;
  * the scanned source root exists and is non-empty (so a moved/renamed tree can't pass vacuously).
"""
from __future__ import annotations

import ast
import pathlib

import pytest

pytestmark = pytest.mark.invariant

SRC = pathlib.Path(__file__).resolve().parents[2] / "nabu_agent"
GATEWAY = "shell_gateway.py"


def _py_files() -> list[pathlib.Path]:
    return sorted(SRC.rglob("*.py"))


def test_source_root_exists_and_nonempty() -> None:
    assert SRC.is_dir(), f"package root missing: {SRC}"
    assert _py_files(), "no python files found — a renamed tree must not pass vacuously"


def _is_shell_run(node: ast.AST) -> bool:
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "run" and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "shell")


def test_only_gateway_calls_shell_run() -> None:
    offenders: list[str] = []
    for path in _py_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        if any(_is_shell_run(n) for n in ast.walk(tree)) and path.name != GATEWAY:
            offenders.append(path.name)
    assert not offenders, f"shell.run called outside {GATEWAY}: {offenders}"


def test_no_subprocess_or_shell_true() -> None:
    banned_attr = {"system", "popen", "spawn", "spawnl", "spawnv"}
    offenders: list[str] = []
    for path in _py_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import) and any(a.name in {"subprocess", "pty"} for a in node.names):
                offenders.append(f"{path.name}: import subprocess/pty")
            if isinstance(node, ast.ImportFrom) and node.module in {"subprocess", "pty"}:
                offenders.append(f"{path.name}: from subprocess/pty import")
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        offenders.append(f"{path.name}: shell=True")
                if isinstance(node.func, ast.Attribute) and node.func.attr in banned_attr \
                        and isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                    offenders.append(f"{path.name}: os.{node.func.attr}(")
    assert not offenders, "home-grown exec path found:\n" + "\n".join(offenders)


def test_engine_import_is_headless() -> None:
    """Importing the engine modules the adapter uses must never pull in Qt.

    Checked in a FRESH interpreter (subprocess) so the result is independent of pytest plugins that
    may themselves import PySide6 — e.g. the classic engine's own dev venv carries ``pytest-qt``,
    which loads PySide6 at startup and would otherwise pollute this session's ``sys.modules``.
    """
    import subprocess  # noqa: PLC0415 - test-side isolation; not part of the scanned SRC tree
    import sys

    probe = (
        "import sys\n"
        "import oscprecon.shell, oscprecon.profile, oscprecon.reporter, oscprecon.service_enum\n"
        "sys.exit(1 if 'PySide6' in sys.modules else 0)\n"
    )
    result = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True)
    if result.returncode == 3 or "ModuleNotFoundError" in result.stderr:
        pytest.skip("engine not installed in this environment")
    assert result.returncode == 0, "importing the engine loaded PySide6 (must stay headless)"
