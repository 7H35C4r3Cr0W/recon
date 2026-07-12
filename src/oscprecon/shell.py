from __future__ import annotations

import logging
import shlex
import shutil
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

logger = logging.getLogger("oscprecon.shell")

# why: shell.run is the sole exec chokepoint, so it is where CLAUDE.md §2 exam-legality is
# enforced. Only these binaries may run; anything else is refused before execution.
ALLOWED_TOOLS: frozenset[str] = frozenset(
    {
        "nmap",
        "feroxbuster",
        "gobuster",
        "ffuf",
        "dirsearch",
        "dirb",
        "nikto",
        "whatweb",
        "curl",
        "wget",
        "wpscan",
        "ssh",
        "enum4linux-ng",
        "enum4linux",
        "smbclient",
        "smbmap",
        "rpcclient",
        "rpcinfo",
        "netexec",
        "nxc",
        "crackmapexec",
        "ldapsearch",
        "snmpwalk",
        "onesixtyone",
        "dnsrecon",
        "dig",
        "dnsenum",
        "wfuzz",
        "ike-scan",
        "nmblookup",
        "nbtscan",
        "ntpq",
        "ntpdate",
        "showmount",
        "rsync",
        "finger",
        "searchsploit",
        "GetADUsers.py",
        "GetNPUsers.py",
        "GetUserSPNs.py",
        "impacket-GetADUsers.py",
        "impacket-GetNPUsers.py",
        "impacket-GetUserSPNs.py",
        # read-only impacket enum scripts (§2 "impacket enum scripts", no cracking on-host)
        "impacket-samrdump",
        "impacket-lookupsid",
        "impacket-rpcdump",
        "impacket-mssqlclient",
        # read-only service enum tools (behaviourally equivalent to already-allowed enum)
        "ssh-audit",
        "snmp-check",
        "snmpbulkwalk",
        "windapsearch",
        "ldapdomaindump",
        "svn",
        "iscsiadm",
        # database clients — unauth read-only enum + single default-cred (Tier-2); no list-brute flag
        "redis-cli",
        "mongosh",
        "mongo",
        "mysql",
        "psql",
    }
)

# why: forbidden even on an allowed binary — brute/spray is banned (§2). '--rid-brute' is NOT
# here: RID cycling is recon (§11), so the check is precise, not a blanket 'brute' match.
_FORBIDDEN_FLAGS: frozenset[str] = frozenset({"--continue-on-success", "--passwords"})

# why: searchsploit is display-only (§14) — these flags copy/open/update a PoC, not display it.
_SEARCHSPLOIT_FORBIDDEN: frozenset[str] = frozenset(
    {"-m", "--mirror", "-x", "--examine", "-u", "--update"}
)

# why: wpscan is enumeration-only (§9) — -P/--passwords + -U/--usernames drive a credential
# brute. --passwords is also in _FORBIDDEN_FLAGS; the short -P alias must be blocked too.
_WPSCAN_FORBIDDEN: frozenset[str] = frozenset({"-P", "--passwords", "-U", "--usernames"})


# why: ike-scan is IKE/ISAKMP detection only (§12). -P/--pskcrack writes the aggressive-mode PSK
# hash to a file for offline cracking — banned. -P takes its file concatenated (`-Pfile`, no space),
# so the short form must be matched by prefix, not equality.
def _ike_scan_violation(argv: list[str]) -> str | None:
    for token in argv[1:]:
        if token.startswith("-P") or token == "--pskcrack" or token.startswith("--pskcrack="):
            return "ike-scan -P/--pskcrack captures the PSK hash for offline cracking (forbidden)"
    return None


# why: netexec is enum/single-cred only (§11 Tier-1/2). Its -u/-p are argparse nargs='+' and
# "user x password" spraying is the DEFAULT, so Tier-3 hides three ways a naive single-token check
# misses: >1 inline value, a value in 2nd+ position, and '='/concatenated syntax. _netexec_violation
# handles all three; a single inline literal (`-p ''`, `-p sa`) stays allowed (the Tier-1/2 check).
_NETEXEC_TOOLS: frozenset[str] = frozenset({"netexec", "nxc", "crackmapexec"})
_NETEXEC_AUTH_FLAGS: frozenset[str] = frozenset({"-u", "--username", "-p", "--password"})


def _netexec_violation(argv: list[str]) -> str | None:
    i = 1
    while i < len(argv):
        token = argv[i]
        flag, sep, inline = token.partition("=")
        if sep:  # `-p=X` / `--password=X`
            values = [inline]
            i += 1
        elif not token.startswith("--") and len(token) > 2 and token[:2] in _NETEXEC_AUTH_FLAGS:
            flag, values = token[:2], [token[2:]]  # concatenated short form: `-pX`
            i += 1
        elif flag in _NETEXEC_AUTH_FLAGS:  # `-p X [Y ...]` — consume the whole nargs='+' run
            i += 1
            values = []
            while i < len(argv) and not argv[i].startswith("-"):
                values.append(argv[i])
                i += 1
        else:
            i += 1
            continue
        literals = [v for v in values if v]
        if len(literals) > 1:
            return f"netexec {flag} has {len(literals)} inline credentials — spray (forbidden)"
        for value in values:
            if value and Path(value).is_file():
                return f"netexec {flag} {value} is a list file — credential brute (forbidden)"
    return None


_INSTALL_HINTS: dict[str, str] = {
    "nmap": "apt install nmap",
    "feroxbuster": "apt install feroxbuster",
    "gobuster": "apt install gobuster",
    "ffuf": "apt install ffuf",
    "nikto": "apt install nikto",
    "whatweb": "apt install whatweb",
    "smbclient": "apt install smbclient",
    "netexec": "apt install netexec",
    "enum4linux-ng": "apt install enum4linux-ng",
    "enum4linux": "apt install enum4linux",
    "snmpwalk": "apt install snmp",
    "onesixtyone": "apt install onesixtyone",
    "searchsploit": "apt install exploitdb",
    "showmount": "apt install nfs-common",
    "rpcinfo": "apt install rpcbind",
    "ntpq": "apt install ntpsec",
    "ntpdate": "apt install ntpsec-ntpdate",
    "impacket-samrdump": "apt install impacket-scripts",
    "impacket-lookupsid": "apt install impacket-scripts",
    "impacket-rpcdump": "apt install impacket-scripts",
    "impacket-mssqlclient": "apt install impacket-scripts",
    "ssh-audit": "apt install ssh-audit",
    "snmp-check": "apt install snmpcheck",
    "snmpbulkwalk": "apt install snmp",
    "windapsearch": "pipx install windapsearch-py  (or git clone ropnop/windapsearch)",
    "ldapdomaindump": "apt install python3-ldapdomaindump",
    "svn": "apt install subversion",
    "iscsiadm": "apt install open-iscsi",
    "redis-cli": "apt install redis-tools",
    "mongosh": "apt install mongodb-mongosh",
    "mongo": "apt install mongodb-clients",
    "mysql": "apt install default-mysql-client",
    "psql": "apt install postgresql-client",
}


def install_hint(tool: str) -> str:
    return _INSTALL_HINTS.get(tool, f"apt install {tool}")


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _script_values(argv: list[str]) -> list[str]:
    values: list[str] = []
    for index, token in enumerate(argv):
        if token == "--script" and index + 1 < len(argv):
            values.append(argv[index + 1])
        elif token.startswith("--script="):
            values.append(token.split("=", 1)[1])
    return values


def policy_violation(argv: list[str]) -> str | None:
    if not argv:
        return "empty command"
    tool = argv[0]
    if tool not in ALLOWED_TOOLS:
        return f"{tool} is not on the OSCP-allowed tool list"
    for token in argv[1:]:
        if token.lower() in _FORBIDDEN_FLAGS:
            return f"{token} is a credential brute/spray flag (forbidden)"
    if tool == "nmap":
        for value in _script_values(argv):
            if "brute" in value.lower():
                return f"nmap --script {value} is credential brute force (forbidden)"
    if tool == "searchsploit":
        for token in argv[1:]:
            if token in _SEARCHSPLOIT_FORBIDDEN:
                return f"searchsploit {token} is not display-only (forbidden)"
    if tool == "wpscan":
        for token in argv[1:]:
            if token in _WPSCAN_FORBIDDEN:
                return f"wpscan {token} is credential brute (forbidden — enumerate only)"
    if tool in _NETEXEC_TOOLS:
        netexec_violation = _netexec_violation(argv)
        if netexec_violation is not None:
            return netexec_violation
    if tool == "ike-scan":
        ike_violation = _ike_scan_violation(argv)
        if ike_violation is not None:
            return ike_violation
    if tool == "ntpdate" and "-q" not in argv[1:]:
        # why: ntpdate WITHOUT -q SETS the local clock (modifies local state, needs root). Recon is
        # query-only — the module always passes -q; back-stop it here for the custom-command path.
        return "ntpdate without -q sets the local clock (forbidden — recon-only)"
    return None


@dataclass
class ShellResult:
    shell_line: str
    exit_code: int
    output_file: Path
    started_at: str
    finished_at: str
    duration_s: float
    missing_tool: str | None = None
    blocked: str | None = None
    cancelled: bool = False


def run(
    shell_line: str,
    output_file: Path,
    *,
    cwd: Path | None = None,
    timeout: float | None = None,
    cancel: threading.Event | None = None,
    on_line: Callable[[str], None] | None = None,
) -> ShellResult:
    argv = shlex.split(shell_line)
    tool = argv[0] if argv else ""
    output_file = Path(output_file)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    started = _now_iso()
    start = time.monotonic()

    violation = policy_violation(argv)
    if violation is not None:
        message = f"[blocked] {violation}: {shell_line}"
        logger.warning(message)
        output_file.write_text(message + "\n", encoding="utf-8")
        if on_line is not None:
            on_line(message)
        return ShellResult(
            shell_line, 126, output_file, started, _now_iso(), 0.0, blocked=violation
        )

    if shutil.which(tool) is None:
        message = f"[missing] {tool} — install with: {install_hint(tool)}"
        logger.warning(message)
        output_file.write_text(message + "\n", encoding="utf-8")
        if on_line is not None:
            on_line(message)
        return ShellResult(
            shell_line, 127, output_file, started, _now_iso(), 0.0, missing_tool=tool
        )

    logger.info("run: %s", shell_line)
    # why: stdin=DEVNULL + start_new_session detach the child from the launching terminal, so a
    # wrapped tool can never block on stdin or /dev/tty for interactive input (e.g. an ssh password
    # prompt). Without this a single interactive command hangs the streaming read loop forever and
    # wedges the GUI's sole worker slot; here it fails fast ("no tty present") instead.
    proc = subprocess.Popen(
        argv,
        cwd=str(cwd) if cwd is not None else None,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
        start_new_session=True,
    )

    timed_out = False
    cancelled = False
    watchdog: threading.Timer | None = None
    if timeout is not None:
        # why: the streaming read blocks until the child closes stdout, so proc.wait(timeout=)
        # can never bound a hung tool — an independent timer that kills the process is the only
        # way to make `timeout` a real deadline.
        def _kill() -> None:
            nonlocal timed_out
            timed_out = True
            proc.kill()

        watchdog = threading.Timer(timeout, _kill)
        watchdog.start()

    monitor: threading.Thread | None = None
    if cancel is not None:
        cancel_event = cancel

        def _watch_cancel() -> None:
            nonlocal cancelled
            # why: the read loop blocks in the pipe, so a side thread is the only way a cancel
            # takes effect promptly — poll the child and kill it the moment the event is set.
            while proc.poll() is None:
                if cancel_event.wait(0.2):
                    cancelled = True
                    proc.kill()
                    return

        monitor = threading.Thread(target=_watch_cancel, daemon=True)
        monitor.start()

    exit_code = -1
    try:
        with output_file.open("w", encoding="utf-8") as handle:
            stream = proc.stdout
            assert stream is not None
            for line in stream:
                handle.write(line)
                if on_line is not None:
                    on_line(line.rstrip("\n"))
        exit_code = proc.wait()
    finally:
        if watchdog is not None:
            watchdog.cancel()
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        if monitor is not None:
            monitor.join(timeout=1.0)

    if timed_out and on_line is not None:
        on_line(f"[timeout] killed after {timeout}s")
    if cancelled and on_line is not None:
        on_line("[cancelled] killed on request")

    return ShellResult(
        shell_line,
        exit_code,
        output_file,
        started,
        _now_iso(),
        time.monotonic() - start,
        cancelled=cancelled,
    )
