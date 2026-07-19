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
    optional: bool = False  # True = not needed for default recon (Spray-mode or Exploitation tab)
    category: str = "recon"  # "recon" | "spray" | "exploit"


@dataclass(frozen=True)
class DoctorReport:
    tools: tuple[ToolStatus, ...]

    @property
    def missing(self) -> list[ToolStatus]:
        return [tool for tool in self.tools if not tool.present]

    @property
    def found(self) -> list[ToolStatus]:
        return [tool for tool in self.tools if tool.present]

    @property
    def required(self) -> list[ToolStatus]:
        return [tool for tool in self.tools if not tool.optional]

    @property
    def optional(self) -> list[ToolStatus]:
        return [tool for tool in self.tools if tool.optional]

    @property
    def spray(self) -> list[ToolStatus]:
        return [tool for tool in self.tools if tool.category == "spray"]

    @property
    def exploit(self) -> list[ToolStatus]:
        return [tool for tool in self.tools if tool.category == "exploit"]


# Interchangeable tools: if ANY member is on PATH, the others aren't real gaps. The FIRST member is
# PREFERRED — the one installed when the whole group is missing (so we never pull deprecated
# crackmapexec when netexec covers it). Mirrors the CLI's "alternatives are fine to skip" note.
_ALTERNATIVE_GROUPS: tuple[tuple[str, frozenset[str]], ...] = (
    ("netexec", frozenset({"netexec", "nxc", "crackmapexec"})),
    ("impacket-GetADUsers.py", frozenset({"GetADUsers.py", "impacket-GetADUsers.py"})),
    ("impacket-GetNPUsers.py", frozenset({"GetNPUsers.py", "impacket-GetNPUsers.py"})),
    ("impacket-GetUserSPNs.py", frozenset({"GetUserSPNs.py", "impacket-GetUserSPNs.py"})),
)


def _group_for(tool: str) -> tuple[str, frozenset[str]] | None:
    for preferred, members in _ALTERNATIVE_GROUPS:
        if tool in members:
            return preferred, members
    return None


def effective_missing(report: DoctorReport) -> list[ToolStatus]:
    # Real gaps only: a tool covered by a present alternative isn't missing, and a wholly-missing
    # group is represented ONCE by its preferred member (so we install one package, not three).
    present = {tool.name for tool in report.found}
    by_name = {tool.name: tool for tool in report.tools}
    result: list[ToolStatus] = []
    seen_groups: set[frozenset[str]] = set()
    for tool in report.missing:
        group = _group_for(tool.name)
        if group is None:
            result.append(tool)
            continue
        preferred, members = group
        if members & present or members in seen_groups:
            continue
        seen_groups.add(members)
        result.append(by_name.get(preferred, tool))
    return result


# Exploitation-tab (§2b) tools: they run only in the human-confirmed exploit mode (which bypasses
# the recon allow-list), so they are NOT in ALLOWED_TOOLS and the doctor would otherwise never tell
# you they're missing. Reported as optional/informational — a recon-only user isn't missing
# anything, but an exam-prep user wants to know these are present before they need them. Never
# auto-installed (they span apt/pipx/gem); the hints are shown so you install the ones you use.
# Binary names are the Kali defaults; the impacket-* group is one `impacket-scripts`/pipx install.
_EXPLOIT_TOOLS: tuple[tuple[str, str], ...] = (
    ("impacket-secretsdump", "apt install impacket-scripts   (or: pipx install impacket)"),
    ("impacket-psexec", "apt install impacket-scripts"),
    ("impacket-wmiexec", "apt install impacket-scripts"),
    ("impacket-smbexec", "apt install impacket-scripts"),
    ("impacket-ntlmrelayx", "apt install impacket-scripts"),
    ("evil-winrm", "gem install evil-winrm   (or: apt install evil-winrm)"),
    ("certipy", "pipx install certipy-ad"),
    ("responder", "apt install responder"),
    ("hashcat", "apt install hashcat"),
    ("john", "apt install john"),
    ("bloodhound-python", "pipx install bloodhound"),
    ("nc", "apt install netcat-traditional"),
)


def scan() -> DoctorReport:
    # shutil.which resolved at call time so a test/global monkeypatch of shutil.which takes effect.
    # Spray-mode tools (hydra/medusa) are scanned too but flagged optional — a recon-only user isn't
    # missing anything without them, but a Spray-mode (§2a) user needs to know if they're absent.
    required = tuple(
        ToolStatus(name, shutil.which(name) is not None, shell.install_hint(name))
        for name in sorted(shell.ALLOWED_TOOLS)
    )
    spray = tuple(
        ToolStatus(name, shutil.which(name) is not None, shell.install_hint(name), True, "spray")
        for name in sorted(shell.SPRAY_TOOLS)
    )
    exploit = tuple(
        ToolStatus(name, shutil.which(name) is not None, hint, True, "exploit")
        for name, hint in _EXPLOIT_TOOLS
    )
    return DoctorReport(required + spray + exploit)


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
    for tool in effective_missing(report):
        if tool.optional:
            continue  # never auto-install a Spray-mode tool for a recon user; surface it separately
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
    # why: this is a package INSTALL, not a recon tool run — it deliberately does NOT go through
    # shell.run (§24's chokepoint), which allow-lists only §2 recon binaries and would (correctly)
    # refuse `apt-get`. argv here is a fixed `[sudo?] apt-get install -y <curated packages>` — the
    # verb is constant and every package name comes from a strict-regex-parsed allow-listed hint, so
    # there is no shell and no user input to smuggle. argv list, never shell=True.
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
    command = " ".join(plan.apt_argv())
    # why: one apt-get per package, not a batch — a single unavailable/renamed package (e.g.
    # crackmapexec on current Kali) would abort a batched transaction and install NOTHING.
    echo(
        f"[doctor] will install {len(plan.packages)} package(s), each independently so one "
        "unavailable package can't block the rest:"
    )
    echo(f"  {command}")
    if not assume_yes and (confirm is None or not confirm(command)):
        echo("[doctor] install cancelled.")
        return 1
    run = runner or _default_runner
    prefix = _sudo_prefix()
    installed: list[str] = []
    failed: list[str] = []
    for package in plan.packages:
        try:
            code = run([*prefix, "apt-get", "install", "-y", package])
        except OSError as exc:
            # apt-get/sudo missing (non-Kali host) or otherwise not runnable — never crash; tell the
            # user the exact command to run themselves.
            echo(f"[doctor] could not launch the installer ({exc}); run it yourself:\n  {command}")
            return 1
        if code == 0:
            installed.append(package)
            echo(f"[doctor] installed {package}")
        else:
            failed.append(package)
            echo(f"[doctor] {package}: apt-get exited {code} — skipped, continuing")
    tail = f", {len(failed)} failed ({', '.join(failed)})" if failed else ""
    echo(f"[doctor] done: {len(installed)} installed{tail}")
    return 1 if failed else 0
