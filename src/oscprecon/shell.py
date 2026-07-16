from __future__ import annotations

import logging
import os
import re
import shlex
import shutil
import signal
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

logger = logging.getLogger("oscprecon.shell")

# Redact credential-bearing tokens before a command line is LOGGED or written to a blocked/missing
# output file — secrets must never persist in the diagnostics log or on disk (CLAUDE.md). The run
# argv is untouched; only the string we log/echo is masked. -p/-a/-w/-H are overloaded (nmap=ports,
# feroxbuster -w=wordlist), so their values are masked only for known credential tools; --password /
# --pass are unambiguous and masked for any tool.
_CRED_TOOLS: frozenset[str] = frozenset(
    {
        "mysql",
        "mysqladmin",
        "psql",
        "redis-cli",
        "netexec",
        "nxc",
        "crackmapexec",
        "hydra",
        "medusa",
        "smbmap",
        "evil-winrm",
        "mssqlclient",
        "ldapsearch",
        "wpscan",
    }
)
_SECRET_VALUE_FLAGS: frozenset[str] = frozenset({"-p", "-a", "-w", "-H", "--hashes"})


def _mask(value: str) -> str:
    return f"<redacted len={len(value)}>"


def _redact_cmdline(argv: list[str]) -> str:
    if not argv:
        return ""
    base = os.path.basename(argv[0]).lower()
    cred_tool = base in _CRED_TOOLS or base.startswith("impacket-")
    out: list[str] = []
    i = 0
    while i < len(argv):
        tok = argv[i]
        head = tok.split("=", 1)[0]
        next_is_secret = (head in ("--password", "--pass")) or (
            cred_tool and tok in _SECRET_VALUE_FLAGS
        )
        if "=" in tok and head in ("--password", "--pass"):
            out.append(f"{head}={_mask(tok.split('=', 1)[1])}")
        elif next_is_secret and i + 1 < len(argv):
            out += [tok, _mask(argv[i + 1])]
            i += 2
            continue
        elif (
            cred_tool
            and len(tok) > 2
            and not tok.startswith("--")
            and tok[:2] in ("-p", "-a", "-H")
        ):
            out.append(f"{tok[:2]}{_mask(tok[2:])}")
        else:
            out.append(tok)
        i += 1
    return " ".join(out)


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
        "openssl",  # s_client TLS banner/cert grab — passive read-only recon
        "windapsearch",
        "ldapdomaindump",
        "svn",
        "iscsiadm",
        # database clients — unauth read-only enum + single default-cred (Tier-2), no list-brute
        "redis-cli",
        "mongosh",
        "mongo",
        "mysql",
        "psql",
        # awscli — read-only S3 bucket enumeration only (§12 cloud recon); write/transfer/other-
        # service subcommands are blocked by _aws_violation. Never uploads/deletes/downloads.
        "aws",
    }
)

# why: forbidden on an allowed binary in the DEFAULT (recon-only) mode — brute/spray is off by
# default (§2). '--rid-brute' is NOT here: RID cycling is recon (§11), so the check is precise, not
# a blanket 'brute' match. In opt-in Spray mode (policy_violation(spray=True)) these are permitted.
_FORBIDDEN_FLAGS: frozenset[str] = frozenset({"--continue-on-success", "--passwords"})

# why: OSCP-legal credential-spraying binaries (§2a). Permitted ONLY in Spray mode
# (policy_violation(spray=True), i.e. config.spray_enabled). Off everywhere else.
SPRAY_TOOLS: frozenset[str] = frozenset({"hydra", "medusa"})

# why: the DB clients are allow-listed for read-only enum (§12), but the custom-command path lets a
# user hand-type a query — refuse file-write / read / OS-exec / DDL primitives (not recon).
_DB_CLIENTS: frozenset[str] = frozenset({"mysql", "psql", "mongosh", "mongo", "redis-cli"})
# plain file/OS primitives (any DB client): substring-matched on the normalised query. The PG
# pg_*_file / pg_ls_*dir family is a regex below (variants like pg_read_binary_file evade a substr).
_DB_FORBIDDEN_SUBSTR: tuple[str, ...] = (
    "into outfile",
    "into dumpfile",
    "load_file",
    "sys_exec",
    "sys_eval",
    "lo_import",
    "lo_export",
    "\\!",
)
# PostgreSQL server-modifying / file / OS primitives — a keyword regex, NOT a blunt substring, so
# read-only enum (SELECT ... FROM pg_database / pg_roles, current_user) is never blocked by chance.
# Comments are stripped and whitespace normalised first (below), so /**/ and tab/newline variants +
# tagged dollar-quotes (DO $body$…$body$) cannot split keywords. The COPY branch requires COPY to be
# followed by a target (a `(` or a non-keyword identifier), so `SELECT copy FROM t` (a column named
# copy) is NOT blocked while `COPY t TO`/`COPY (SELECT …) TO PROGRAM` is.
_PG_FORBIDDEN_RE = re.compile(
    r"\bcopy\s*(?:\(|(?!(?:from|to|program|select|with)\b)[\"a-z_])[^;]*\b(?:to|from|program)\b"
    r"|\bcreate\s+(?:or\s+replace\s+)?(?:function|extension|role|database|user)\b"
    r"|\bdrop\s+(?:role|user|database|function|extension)\b"
    r"|\balter\s+(?:role|user)\b"
    r"|\bgrant\b[^;]*\bpg_(?:read|write|execute)_server\w*\b"
    r"|\bdo\b[^;]*\$[a-z0-9_]*\$"
    r"|\bpg_(?:read|write)_(?:binary_)?file\b"
    r"|\bpg_ls_\w*dir\b"
    r"|\bpg_stat_file\b",
)


def _db_primitive_violation(tool: str, argv: list[str]) -> str | None:
    raw = " ".join(argv[1:])
    # strip SQL comments (block + line) BEFORE collapsing whitespace, so a comment can't hide/split
    # a keyword; PostgreSQL treats a comment as whitespace, so this mirrors the server's own lexer.
    raw = re.sub(r"/\*.*?\*/", " ", raw, flags=re.DOTALL)
    raw = re.sub(r"--[^\n]*", " ", raw)
    joined = re.sub(r"\s+", " ", raw).lower()
    for primitive in _DB_FORBIDDEN_SUBSTR:
        if primitive in joined:
            return f"{tool} {primitive.strip()} is a file/OS primitive, not recon (forbidden)"
    hit = _PG_FORBIDDEN_RE.search(joined)
    if hit is not None:
        return f"{tool} '{hit.group(0)}' modifies the server / runs code, not recon (forbidden)"
    return None


# why: searchsploit is display-only (§14) — these flags copy/open/update a PoC, not display it.
_SEARCHSPLOIT_FORBIDDEN: frozenset[str] = frozenset(
    {"-m", "--mirror", "-x", "--examine", "-u", "--update"}
)

# why: wpscan is enumeration-only (§9) — -P/--passwords + -U/--usernames drive a credential
# brute. --passwords is also in _FORBIDDEN_FLAGS; the short -P alias must be blocked too.
_WPSCAN_FORBIDDEN: frozenset[str] = frozenset({"-P", "--passwords", "-U", "--usernames"})

# why: awscli is allow-listed for READ-ONLY S3 enumeration only (§12). Allow-list the safe verbs
# rather than block-list the dangerous ones: `s3 ls` and `s3api list-*/head-*/get-bucket-*` LIST
# metadata; everything else (cp/mv/rm/sync/website/presign, put-/create-/delete-*, get-object which
# downloads, and every non-S3 service) can write, exfiltrate, or leave recon scope — refuse it.
_AWS_S3_READONLY: frozenset[str] = frozenset({"ls"})
_AWS_S3API_READONLY_PREFIXES: tuple[str, ...] = ("list-", "head-", "get-bucket-", "get-object-acl")
# flags that take a following value, so that value is not mistaken for the service/operation token
_AWS_VALUE_FLAGS: frozenset[str] = frozenset(
    {"--endpoint", "--endpoint-url", "--region", "--profile", "--output", "--bucket", "--prefix"}
)


def _aws_positional(argv: list[str]) -> list[str]:
    positional: list[str] = []
    skip = False
    for token in argv[1:]:
        if skip:
            skip = False
            continue
        if token.startswith("-"):
            if token in _AWS_VALUE_FLAGS:  # `--endpoint http://x` (space form): skip its value too
                skip = True
            continue
        positional.append(token)
    return positional


def _aws_violation(argv: list[str]) -> str | None:
    positional = _aws_positional(argv)
    if not positional:
        return "aws needs a read-only S3 subcommand (s3 ls / s3api list-*)"
    service = positional[0]
    if service == "configure":
        return None  # local credential setup only — touches ~/.aws, never the target
    if service not in ("s3", "s3api"):
        return f"aws {service} is not S3 read-only recon (only s3 / s3api enumeration)"
    op = positional[1] if len(positional) > 1 else ""
    if service == "s3":
        if op not in _AWS_S3_READONLY:
            return f"aws s3 {op or '<none>'} is not read-only (only `aws s3 ls`)"
    elif not op.startswith(_AWS_S3API_READONLY_PREFIXES):
        return (
            f"aws s3api {op or '<none>'} is not read-only enumeration (list-*/head-*/get-bucket-*)"
        )
    return None


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
    "openssl": "apt install openssl",
    "hydra": "apt install hydra",
    "medusa": "apt install medusa",
    "redis-cli": "apt install redis-tools",
    "mongosh": "apt install mongodb-mongosh",
    "mongo": "apt install mongodb-clients",
    "mysql": "apt install default-mysql-client",
    "psql": "apt install postgresql-client",
    "aws": "apt install awscli",
    "GetADUsers.py": "apt install python3-impacket",
    "GetNPUsers.py": "apt install python3-impacket",
    "GetUserSPNs.py": "apt install python3-impacket",
    "impacket-GetADUsers.py": "apt install impacket-scripts",
    "impacket-GetNPUsers.py": "apt install impacket-scripts",
    "impacket-GetUserSPNs.py": "apt install impacket-scripts",
    "crackmapexec": "apt install crackmapexec  (or use netexec)",
    "nxc": "apt install netexec",
    "dirb": "apt install dirb",
    "wget": "apt install wget",
    "wpscan": "apt install wpscan",
    "ssh": "apt install openssh-client",
    "smbmap": "apt install smbmap",
    "rpcclient": "apt install smbclient",
    "ldapsearch": "apt install ldap-utils",
    "dnsrecon": "apt install dnsrecon",
    "dig": "apt install dnsutils",
    "dnsenum": "apt install dnsenum",
    "wfuzz": "apt install wfuzz",
    "ike-scan": "apt install ike-scan",
    "nmblookup": "apt install smbclient",
    "nbtscan": "apt install nbtscan",
    "finger": "apt install finger",
    "rsync": "apt install rsync",
    "curl": "apt install curl",
    "dirsearch": "apt install dirsearch",
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


def policy_violation(argv: list[str], *, spray: bool = False) -> str | None:
    # `spray=True` ONLY when the user enabled opt-in Spray mode (§2a) and the command came from the
    # spray subsystem. It loosens EXACTLY the credential-attempt category (brute/spray tools+flags);
    # everything else — Metasploit/SQLMap/commercial (not on any list), DB file/OS primitives,
    # searchsploit PoC copy, ike-scan PSK capture, ntpdate clock-set — stays blocked either way.
    if not argv:
        return "empty command"
    tool = argv[0]
    allowed = ALLOWED_TOOLS | SPRAY_TOOLS if spray else ALLOWED_TOOLS
    if tool not in allowed:
        return f"{tool} is not on the OSCP-allowed tool list"
    if not spray:
        for token in argv[1:]:
            if token.lower() in _FORBIDDEN_FLAGS:
                return (
                    f"{token} is a credential brute/spray flag (off by default — enable Spray mode)"
                )
    if tool == "nmap":
        for value in _script_values(argv):
            if "brute" in value.lower() and not spray:
                return f"nmap --script {value} is credential brute (off by default — Spray mode)"
    if tool == "searchsploit":
        for token in argv[1:]:
            if token in _SEARCHSPLOIT_FORBIDDEN:
                return f"searchsploit {token} is not display-only (forbidden)"
    if tool == "aws":
        aws_violation = _aws_violation(argv)
        if aws_violation is not None:
            return aws_violation
    if tool == "wpscan" and not spray:
        for token in argv[1:]:
            if token in _WPSCAN_FORBIDDEN:
                return f"wpscan {token} is credential brute (off by default — enable Spray mode)"
    if tool in _NETEXEC_TOOLS and not spray:
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
    if tool in _DB_CLIENTS:
        db_violation = _db_primitive_violation(tool, argv)
        if db_violation is not None:
            return db_violation
    return None


def _terminate(proc: subprocess.Popen[str]) -> None:
    # why: start_new_session makes proc.pid a process-group leader, so kill the whole group — else
    # helpers a tool forks (enum4linux-ng -> smbclient/rpcclient, dnsenum -> dig) survive as orphans
    # and can hold the stdout pipe open, so the read loop never hits EOF and timeout/cancel never
    # actually lands. try/except guards the OS boundary (the group may already be gone).
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        proc.kill()


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
    spray: bool = False,
) -> ShellResult:
    output_file = Path(output_file)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    started = _now_iso()
    start = time.monotonic()

    # an unbalanced quote must fail gracefully at this chokepoint, not raise into the worker thread
    try:
        argv = shlex.split(shell_line)
    except ValueError:
        message = "[blocked] unparseable command line (unbalanced quotes)"
        logger.warning(message)
        output_file.write_text(message + "\n", encoding="utf-8")
        if on_line is not None:
            on_line(message)
        return ShellResult(
            shell_line,
            126,
            output_file,
            started,
            _now_iso(),
            0.0,
            blocked="unparseable command line",
        )
    tool = argv[0] if argv else ""
    redacted = _redact_cmdline(argv)  # secret-free string for logging / disk

    violation = policy_violation(argv, spray=spray)
    if violation is not None:
        message = f"[blocked] {violation}: {redacted}"
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

    logger.info("run: %s", redacted)
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
            _terminate(proc)

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
                    _terminate(proc)
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
            _terminate(proc)
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
