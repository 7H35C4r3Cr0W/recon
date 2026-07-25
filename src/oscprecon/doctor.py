from __future__ import annotations

import os
import re
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

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
    # the same impacket tool ships under three names depending on how it was installed: the Kali
    # `impacket-scripts` package -> `impacket-GetADUsers` (NO .py, the preferred/installed form),
    # a pip install -> `GetADUsers.py`, older packaging -> `impacket-GetADUsers.py`. ANY of them
    # satisfies the tool; the preferred (first) member is what we'd apt-install if the whole group
    # is absent. Without the no-.py name here, doctor wrongly reported impacket-scripts as missing.
    (
        "impacket-GetADUsers",
        frozenset({"impacket-GetADUsers", "GetADUsers.py", "impacket-GetADUsers.py"}),
    ),
    (
        "impacket-GetNPUsers",
        frozenset({"impacket-GetNPUsers", "GetNPUsers.py", "impacket-GetNPUsers.py"}),
    ),
    (
        "impacket-GetUserSPNs",
        frozenset({"impacket-GetUserSPNs", "GetUserSPNs.py", "impacket-GetUserSPNs.py"}),
    ),
    # same class of bug as impacket: Kali's `certipy-ad` package installs the binary as
    # `certipy-ad`, while a pipx install of the same project gives `certipy`. Either satisfies the
    # ADCS actions — without this, an image that HAS certipy-ad was told certipy was missing.
    ("certipy-ad", frozenset({"certipy-ad", "certipy"})),
    # netcat: Debian/Kali ship the binary as `nc` (netcat-traditional / netcat-openbsd) and nmap
    # ships `ncat`. Any of them is a listener/connector for the shells catalog.
    ("nc", frozenset({"nc", "ncat", "netcat"})),
    # MySQL/MariaDB client: Kali's default-mysql-client provides `mariadb` (with `mysql` as a
    # compatibility symlink on some releases) — either one drives the mysql actions.
    ("mysql", frozenset({"mysql", "mariadb"})),
    # the legacy mongo shell was replaced by mongosh; either can drive the mongodb actions.
    ("mongosh", frozenset({"mongosh", "mongo"})),
)


def _group_for(tool: str) -> tuple[str, frozenset[str]] | None:
    for preferred, members in _ALTERNATIVE_GROUPS:
        if tool in members:
            return preferred, members
    return None


def _on_path(tool: str) -> bool:
    # a tool is present when ANY name in its alternative group is on PATH — the alternative may not
    # be scanned in its own right (Kali installs `certipy-ad`, we look for `certipy`), so checking
    # only the canonical name reported an INSTALLED tool as missing.
    group = _group_for(tool)
    names = sorted(group[1]) if group is not None else [tool]
    return any(shutil.which(name) is not None for name in names)


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
    ("certipy", "apt install certipy-ad   (or: pipx install certipy-ad)"),
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
        ToolStatus(name, _on_path(name), shell.install_hint(name))
        for name in sorted(shell.ALLOWED_TOOLS)
    )
    spray = tuple(
        ToolStatus(name, _on_path(name), shell.install_hint(name), True, "spray")
        for name in sorted(shell.SPRAY_TOOLS)
    )
    exploit = tuple(
        ToolStatus(name, _on_path(name), hint, True, "exploit") for name, hint in _EXPLOIT_TOOLS
    )
    return DoctorReport(required + spray + exploit)


# -------------------------------------------------------------------------------------------------
# Beyond "is the binary on PATH": data files the tools need (wordlists / NSE / exploitdb) and
# exam-day host readiness (VPN up? disk free? can we raw-socket scan?). These are NOT tools — they
# never enter the apt install plan and are reported separately, so scan()'s tool set is unaffected.
# -------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str  # remediation hint (when not ok) or extra info (e.g. free GB)


# (label, path, remediation) — the reference data the wrapped tools rely on.
_RESOURCE_PATHS: tuple[tuple[str, str, str], ...] = (
    ("SecLists wordlists", "/usr/share/seclists", "apt install seclists"),
    ("Standard wordlists", "/usr/share/wordlists", "apt install wordlists"),
    ("NSE scripts (nmap)", "/usr/share/nmap/scripts", "apt install --reinstall nmap"),
    ("Exploit-DB (searchsploit)", "/usr/share/exploitdb", "apt install exploitdb"),
)


def scan_resources() -> tuple[Check, ...]:
    return tuple(Check(name, Path(path).exists(), detail) for name, path, detail in _RESOURCE_PATHS)


def _vpn_up(net_dir: Path = Path("/sys/class/net")) -> bool:
    try:
        return any(iface.name.startswith(("tun", "tap", "ppp")) for iface in net_dir.iterdir())
    except OSError:
        return False


def _free_gb(path: str) -> float:
    # walk up to the nearest existing ancestor so a not-yet-created workspace still reports its disk
    try:
        p = Path(path).expanduser()
        while not p.exists() and p != p.parent:
            p = p.parent
        return shutil.disk_usage(p).free / 1_000_000_000
    except OSError:
        return -1.0


def _nmap_real_binaries(nmap: str) -> list[str]:
    # Kali ships /usr/bin/nmap as a small WRAPPER SCRIPT and puts the capabilities on the real
    # binary (/usr/lib/nmap/nmap). getcap on the wrapper returns nothing, so checking only the
    # PATH entry reported "not privileged" on a host where SYN scans demonstrably work. [review]
    candidates = [nmap]
    resolved = os.path.realpath(nmap)
    if resolved != nmap:
        candidates.append(resolved)
    try:
        with open(resolved, "rb") as handle:
            head = handle.read(4096)
    except OSError:
        head = b""
    if head.startswith(b"#!"):  # a wrapper: take the absolute /…/nmap path it execs
        for token in re.findall(rb"(/[\w./+-]*/nmap)\b", head):
            path = token.decode("utf-8", "replace")
            if path not in candidates:
                candidates.append(path)
    for fallback in ("/usr/lib/nmap/nmap", "/usr/libexec/nmap/nmap"):
        if fallback not in candidates:
            candidates.append(fallback)
    return [c for c in candidates if os.path.exists(c)]


def _nmap_can_raw() -> bool:
    # SYN / UDP / OS scans need raw sockets: root, or nmap granted cap_net_raw via setcap
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return True
    nmap, getcap = shutil.which("nmap"), shutil.which("getcap")
    if not nmap or not getcap:
        return False
    for candidate in _nmap_real_binaries(nmap):
        try:
            out = subprocess.run(  # noqa: S603
                [getcap, candidate], capture_output=True, text=True, timeout=2, check=False
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if "cap_net_raw" in (out.stdout or ""):
            return True
    return False


def scan_system(workspace_root: str | None = None) -> tuple[Check, ...]:
    if workspace_root is None:
        try:
            from oscprecon import config

            workspace_root = str(config.workspace_root())
        except Exception:  # noqa: BLE001 - config read is a boundary; never let it break the doctor
            workspace_root = str(Path.home() / "oscprecon")
    free = _free_gb(workspace_root)
    vpn = _vpn_up()
    raw = _nmap_can_raw()
    return (
        Check(
            "VPN tunnel up (tun/tap)",
            vpn,
            "a tun/tap interface is up"
            if vpn
            else "no tun/tap — connect your lab/exam VPN (e.g. openvpn lab.ovpn) before scanning",
        ),
        Check(
            "Workspace disk space",
            free < 0 or free >= 1.0,  # unknown (-1) → don't alarm
            f"{free:.1f} GB free at {workspace_root}"
            if free >= 0
            else f"could not read {workspace_root}",
        ),
        Check(
            "Raw-socket scans (nmap -sS/-sU/-O)",
            raw,
            "root or nmap has cap_net_raw"
            if raw
            else "not privileged — run with sudo, or: sudo setcap cap_net_raw+eip $(which nmap)",
        ),
    )


# Curated, fast, offline `--version`-style probes for the tools people most want to spot-check. Only
# these run (each timeout-bounded, stdin closed, argv list — never a shell); everything else is
# skipped so the versions pass can't hang or do anything unexpected.
_VERSION_CMD: dict[str, tuple[str, ...]] = {
    "nmap": ("--version",),
    "feroxbuster": ("--version",),
    "ffuf": ("-V",),
    "netexec": ("--version",),
    "nxc": ("--version",),
    "hashcat": ("--version",),
    "curl": ("--version",),
    "wget": ("--version",),
}


def tool_version(name: str) -> str | None:
    flags = _VERSION_CMD.get(name)
    if flags is None or shutil.which(name) is None:
        return None
    try:
        proc = subprocess.run(  # noqa: S603
            [name, *flags],
            capture_output=True,
            text=True,
            timeout=4,
            stdin=subprocess.DEVNULL,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    out = proc.stdout.strip() or proc.stderr.strip()
    first = out.splitlines()[0].strip() if out else ""
    return first[:120] or None


def versions(report: DoctorReport) -> dict[str, str]:
    # best-effort version string for each PRESENT tool we have a curated probe for
    result: dict[str, str] = {}
    for tool in report.found:
        version = tool_version(tool.name)
        if version:
            result[tool.name] = version
    return result


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


def _apt_simulate(argv: list[str]) -> tuple[int, str]:
    """Run `apt-get install -s …` and return (exit code, stdout). Seam so callers/tests can
    substitute it — the real one shells out, which a unit test must not do."""
    completed = subprocess.run(  # noqa: S603 - fixed verb, package from a parsed allow-list
        argv,
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "LC_ALL": "C", "DEBIAN_FRONTEND": "noninteractive"},
    )
    return completed.returncode, completed.stdout


def _would_remove_or_downgrade(
    simulate: Callable[[list[str]], tuple[int, str]],
    prefix: list[str],
    package: str,
    echo: Callable[[str], None],
) -> bool:
    """True when apt would REMOVE or DOWNGRADE something to install `package`.

    Mirrors install.sh's dry-run refusal. Uses `apt-get -s` (no root needed, changes nothing) and
    reads the plan; LC_ALL=C so the markers are matched on a non-English host too.
    """
    try:
        code, stdout = simulate(
            [*prefix, "apt-get", "install", "-s", "--no-install-recommends", package]
        )
    except OSError:
        return False  # can't simulate (no apt) — the real call below will report the failure
    if code != 0:
        echo(f"[doctor] {package}: apt could not compute a safe plan — skipped.")
        return True
    destructive = [
        line
        for line in stdout.splitlines()
        if line.startswith("Remv ") or "DOWNGRADED" in line.upper()
    ]
    if destructive:
        echo(f"[doctor] {package}: SKIPPED — apt wants to remove/downgrade packages to install it:")
        for line in destructive[:6]:
            echo(f"           {line.strip()}")
        return True
    return False


def install(
    plan: InstallPlan,
    *,
    assume_yes: bool = False,
    confirm: Callable[[str], bool] | None = None,
    runner: Callable[[list[str]], int] | None = None,
    simulate: Callable[[list[str]], tuple[int, str]] | None = None,
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
    skipped: list[str] = []
    for package in plan.packages:
        # why: the SAME guard install.sh applies — dry-run first and refuse the package if apt would
        # REMOVE or DOWNGRADE anything to install it. On a rolling Kali that is how a "just install
        # the missing tool" turns into a partial upgrade that breaks the system, and this path had
        # none of the protection the installer advertises. [review]
        unsafe = _would_remove_or_downgrade(simulate or _apt_simulate, prefix, package, echo)
        if unsafe:
            skipped.append(package)
            continue
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
    if skipped:
        tail += f", {len(skipped)} skipped to protect your system ({', '.join(skipped)})"
        echo("[doctor] to install the skipped package(s), update first: sudo apt full-upgrade")
    echo(f"[doctor] done: {len(installed)} installed{tail}")
    return 1 if (failed or skipped) else 0
