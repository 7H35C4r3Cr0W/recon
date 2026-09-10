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


def _dotted(node: ast.AST) -> str:
    """The dotted name of a Name/Attribute chain, e.g. ``oscprecon.shell.run`` (else "")."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def _is_shell_run(node: ast.AST) -> bool:
    # matches shell.run(...) AND oscprecon.shell.run(...) — any attribute call `.run` whose dotted
    # receiver is (or ends in) `shell`. Aliased/`from`-imported forms are blocked by the import ban.
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "run"):
        return False
    recv = _dotted(node.func.value)
    return recv == "shell" or recv.endswith(".shell")


def test_only_gateway_calls_shell_run() -> None:
    offenders: list[str] = []
    for path in _py_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        if any(_is_shell_run(n) for n in ast.walk(tree)) and path.name != GATEWAY:
            offenders.append(path.name)
    assert not offenders, f"shell.run called outside {GATEWAY}: {offenders}"


def test_no_hidden_shell_run_import_outside_gateway() -> None:
    """Close the aliasing/`from`-import bypasses of the shell.run-call check. A plain
    ``import oscprecon.shell`` is allowed (e.g. main.py's headless load-check) because any
    ``oscprecon.shell.run(...)`` call on it is already caught by the dotted-receiver check. Banned
    outside the gateway: ``from oscprecon.shell import run`` (bare `run()` call) and an ALIASED
    ``import oscprecon.shell as X`` (``X.run()`` would otherwise slip past)."""
    offenders: list[str] = []
    for path in _py_files():
        if path.name == GATEWAY:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.name == "oscprecon.shell" and a.asname:
                        offenders.append(f"{path.name}: import oscprecon.shell as {a.asname}")
            if isinstance(node, ast.ImportFrom) and node.module == "oscprecon.shell":
                offenders.append(f"{path.name}: from oscprecon.shell import ...")
    assert not offenders, "hidden shell.run import outside the gateway:\n" + "\n".join(offenders)


def test_no_subprocess_or_shell_true() -> None:
    banned_os = {"system", "popen", "spawn", "spawnl", "spawnv", "spawnlp", "spawnvp", "posix_spawn",
                 "execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp", "execvpe"}
    banned_modules = {"subprocess", "pty"}
    offenders: list[str] = []
    for path in _py_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import) and any(a.name in banned_modules for a in node.names):
                offenders.append(f"{path.name}: import subprocess/pty")
            if isinstance(node, ast.ImportFrom) and node.module in banned_modules:
                offenders.append(f"{path.name}: from subprocess/pty import")
            if isinstance(node, ast.ImportFrom) and node.module == "os" \
                    and any(a.name in banned_os for a in node.names):
                offenders.append(f"{path.name}: from os import <exec/spawn>")
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        offenders.append(f"{path.name}: shell=True")
                if isinstance(node.func, ast.Attribute):
                    recv = _dotted(node.func.value)
                    if recv == "os" and node.func.attr in banned_os:
                        offenders.append(f"{path.name}: os.{node.func.attr}(")
                    if recv == "asyncio" and node.func.attr in {"create_subprocess_exec", "create_subprocess_shell"}:
                        offenders.append(f"{path.name}: asyncio.{node.func.attr}(")
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
