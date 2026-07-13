from __future__ import annotations

import os
import re
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass

from oscprecon import shell

# why: the guided installer must be SAFE — it may only install tools that are on the §2 allow-list,
# via the curated install hint (never a user-supplied string), and only after explicit confirmation.
# We install ONLY packages of the exact form `apt install <pkg>`; a pkg name must match this strict
# pattern (no shell metacharacters), so a hint can never smuggle an arbitrary command. Non-apt hints
# (pipx / git clone / "... (or ...)") are shown as MANUAL, never auto-run.
_APT_PKG_RE = re.compile(r"^apt install ([a-z0-9][a-z0-9.+-]*)\b")


@dataclass(frozen=True)
class ToolStatus:
    name: str
    present: bool
    hint: str


@dataclass(frozen=True)
class DoctorReport:
    tools: tuple[ToolStatus, ...]

    @property
    def missing(self) -> list[ToolStatus]:
        return [tool for tool in self.tools if not tool.present]

    @property
    def found(self) -> list[ToolStatus]:
        return [tool for tool in self.tools if tool.present]


def scan() -> DoctorReport:
    # shutil.which resolved at call time so a test/global monkeypatch of shutil.which takes effect.
    tools = tuple(
        ToolStatus(name, shutil.which(name) is not None, shell.install_hint(name))
        for name in sorted(shell.ALLOWED_TOOLS)
    )
    return DoctorReport(tools)


@dataclass(frozen=True)
class InstallPlan:
    packages: tuple[str, ...]  # deduped apt packages, derived ONLY from allow-listed tools' hints
    manual: tuple[tuple[str, str], ...]  # (tool, hint) needing manual install (pipx/git/...)

    def apt_argv(self) -> list[str]:
        return [*_sudo_prefix(), "apt-get", "install", "-y", *self.packages]


def _apt_package(hint: str) -> str | None:
    match = _APT_PKG_RE.match(hint.strip())
    return match.group(1) if match else None


def install_plan(report: DoctorReport) -> InstallPlan:
    packages: list[str] = []
    manual: list[tuple[str, str]] = []
    seen: set[str] = set()
    for tool in report.missing:
        package = _apt_package(tool.hint)
        if package is None:
            manual.append((tool.name, tool.hint))
        elif package not in seen:
            seen.add(package)
            packages.append(package)
    return InstallPlan(tuple(sorted(packages)), tuple(manual))


def _sudo_prefix() -> list[str]:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return []
    return ["sudo"] if shutil.which("sudo") else []


def _default_runner(argv: list[str]) -> int:
    # argv is [sudo?] apt-get install -y <curated packages> — a fixed verb + allow-listed package
    # names, no shell, no user input.
    return subprocess.run(argv, check=False).returncode  # noqa: S603


def install(
    plan: InstallPlan,
    *,
    assume_yes: bool = False,
    confirm: Callable[[str], bool] | None = None,
    runner: Callable[[list[str]], int] | None = None,
    echo: Callable[[str], None] = print,
) -> int:
    if not plan.packages:
        echo("[doctor] nothing to auto-install via apt.")
        return 0
    argv = plan.apt_argv()
    command = " ".join(argv)
    echo(f"[doctor] will run: {command}")
    if not assume_yes and (confirm is None or not confirm(command)):
        echo("[doctor] install cancelled.")
        return 1
    return (runner or _default_runner)(argv)
