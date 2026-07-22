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

# Owner policy (2026-07-22): NEVER redact. This is the operator's own tool run against their own
# authorized targets, and the loot (hashes, PSKs, passwords) IS the assessment deliverable — hiding
# it is counter-productive. So secret masking is OFF: command logs, the audit trail, reports, spray
# output, and SNMP findings all carry the full value. The masking helpers below are kept intact but
# only fire when this flag is explicitly flipped True (e.g. a future multi-tenant/public build); the
# whole tool ships with it False. See config.Settings.redact_secrets + docs/OWNER_DECISIONS.md.
REDACT_SECRETS = False

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
        "sshpass",
    }
)
_SECRET_VALUE_FLAGS: frozenset[str] = frozenset({"-p", "-a", "-w", "-H", "--hashes"})
# secret-bearing flags whose value is masked for ANY tool (§6 "never log secret values"), not only
# recognised cred tools: impacket scripts pass NT hashes as the single-dash `-hashes LM:NT`, and a
# bare `GetNPUsers.py` isn't in _CRED_TOOLS, so keying redaction off the tool name would leak it.
_SECRET_HEADS: tuple[str, ...] = ("--password", "--pass", "--hashes", "-hashes")


def _mask(value: str) -> str:
    return f"<redacted len={len(value)}>"


# why: secrets also travel INSIDE a single argv token in the credential shapes this tool ships as
# Tier-2 recon commands — `scheme://user:PASS@host` (psql/ftp URIs), bare `DOMAIN/USER:PASS[@tgt]`
# (impacket positionals like GetADUsers.py), and `-U user%PASS` (smbclient/rpcclient). These are
# masked regardless of the tool, since the flag-based logic below never sees them. Over-masking a
# port/host in a log is harmless; leaking a cleartext password is the bug (CLAUDE.md §6).
_URI_CRED_RE = re.compile(r"^([A-Za-z][\w+.-]*://[^:/@\s]+):([^@\s]+)@")
_USER_PCT_RE = re.compile(r"^(--user=|-U)([^%\s]+)%(.+)$")
_IMPACKET_CRED_RE = re.compile(r"^([^/\s:]+/[^/\s:]+):([^@\s]+)(@.*)?$")
# the DOMAINLESS positional `user:PASS@host` — impacket-mssqlclient sa:pw@t, local-account
# psexec/wmiexec (no domain slash), the pymysql/psql `user:pw@host` form. The impacket regex above
# needs a `domain/user`, so this shape leaked in cleartext (bug #8). `@\S+$` (a host tail, anchored)
# keeps it specific to connection strings, not an arbitrary `a:b` token.
_USERPASS_HOST_RE = re.compile(r"^([^/\s:@]+):([^@\s]+)@\S+$")


def _mask_userpct(value: str) -> str:
    # `[DOMAIN\]user%PASSWORD` -> mask only the password after `%` (smbclient/rpcclient/netexec -U)
    user, sep, pw = value.partition("%")
    return f"{user}%{_mask(pw)}" if sep and pw else value


def _mask_secret_shapes(tok: str) -> str:
    m = _URI_CRED_RE.match(tok)
    if m:
        return tok[: m.start(2)] + _mask(m.group(2)) + tok[m.end(2) :]
    m = _USER_PCT_RE.match(tok)
    if m:
        return f"{m.group(1)}{m.group(2)}%{_mask(m.group(3))}"
    if "://" not in tok:
        m = _IMPACKET_CRED_RE.match(tok)
        if m:
            return f"{m.group(1)}:{_mask(m.group(2))}{m.group(3) or ''}"
        m = _USERPASS_HOST_RE.match(tok)  # domainless user:PASS@host (mssqlclient/local-account)
        if m:
            return tok[: m.start(2)] + _mask(m.group(2)) + tok[m.end(2) :]
    return tok


def _redact_cmdline(argv: list[str]) -> str:
    if not argv:
        return ""
    if not REDACT_SECRETS:  # owner policy: show the full command line (secrets included)
        return " ".join(argv)
    base = os.path.basename(argv[0]).lower()
    cred_tool = base in _CRED_TOOLS or base.startswith("impacket-")
    out: list[str] = []
    i = 0
    while i < len(argv):
        tok = argv[i]
        head = tok.split("=", 1)[0]
        next_is_secret = (head in _SECRET_HEADS) or (cred_tool and tok in _SECRET_VALUE_FLAGS)
        if head in ("-U", "--user") and "=" in tok:  # --user=DOMAIN\user%PASS
            out.append(f"{head}={_mask_userpct(tok.split('=', 1)[1])}")
        elif tok in ("-U", "--user") and i + 1 < len(argv):  # -U DOMAIN\user%PASS (split token)
            out += [tok, _mask_userpct(argv[i + 1])]
            i += 2
            continue
        elif "=" in tok and head in _SECRET_HEADS:
            out.append(f"{head}={_mask(tok.split('=', 1)[1])}")
        elif next_is_secret and i + 1 < len(argv):
            # mask the flag's value AND any trailing non-flag tokens (nargs spray: -p p1 p2 p3)
            out.append(tok)
            j = i + 1
            while j < len(argv) and not argv[j].startswith("-"):
                out.append(_mask(argv[j]))
                j += 1
            i = j
            continue
        elif (
            cred_tool
            and len(tok) > 2
            and not tok.startswith("--")
            and tok[:2] in ("-p", "-a", "-H")
        ):
            out.append(f"{tok[:2]}{_mask(tok[2:])}")
        else:
            out.append(_mask_secret_shapes(tok))
        i += 1
    return " ".join(out)


def redact_command(command: str) -> str:
    """Mask secrets in a full shell-line string before it is logged/audited/reported (§6/§18).

    Best-effort: a recon Tier-2 or custom command can embed a vault credential (impacket
    domain/user:pass@host, -p …), and the audit layer only redacts by key-name — so scrub the
    command string itself here. The returned string is for display only (quoting is not preserved).
    """
    if not REDACT_SECRETS:  # owner policy: never redact — return the command verbatim
        return command
    try:
        argv = shlex.split(command)
    except ValueError:
        argv = command.split()  # unbalanced quotes — fall back to a whitespace split
    return _redact_cmdline(argv)


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

# why: nmap NSE scripts whose name contains "brute" but which enumerate a non-credential IDENTIFIER
# (a service SID), not passwords — pure recon, the prerequisite for any auth, like the allowed
# --rid-brute (§11). Everything else matching "brute" (ssh-brute, http-*-brute, …) stays blocked.
_NMAP_RECON_BRUTE: frozenset[str] = frozenset({"oracle-sid-brute"})

# why: OSCP-legal credential-spraying binaries (§2a). Permitted ONLY in Spray mode
# (policy_violation(spray=True), i.e. config.spray_enabled). Off everywhere else.
SPRAY_TOOLS: frozenset[str] = frozenset({"hydra", "medusa"})

# why: the DB clients are allow-listed for read-only enum (§12), but the custom-command path lets a
# user hand-type a query — refuse file-write / read / OS-exec / DDL primitives (not recon).
_DB_CLIENTS: frozenset[str] = frozenset(
    {"mysql", "psql", "mongosh", "mongo", "redis-cli", "impacket-mssqlclient", "mssqlclient.py"}
)
# plain file/OS primitives (any DB client): substring-matched on the normalised query. The PG
# pg_*_file / pg_ls_*dir family is a regex below (variants like pg_read_binary_file evade a substr).
# The MSSQL OS/file primitives (xp_cmdshell / sp_OA* OLE automation / xp_dirtree / OPENROWSET BULK)
# are the MSSQL RCE-in-recon-mode gap (bug #9) — they are never recon, so a substring block is safe
# (sp_configure is deliberately NOT listed: it also drives legitimate read-only config queries).
_DB_FORBIDDEN_SUBSTR: tuple[str, ...] = (
    "into outfile",
    "into dumpfile",
    "load data",  # LOAD DATA [LOCAL] INFILE — client-side file read into a table
    "load_file",
    "sys_exec",
    "sys_eval",
    "lo_import",
    "lo_export",
    "xp_cmdshell",
    "sp_oacreate",
    "sp_oamethod",
    "xp_dirtree",
    "xp_regwrite",
    "xp_regread",
    "openrowset",
    "bulk insert",
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
_WORDLIST_EXTS: frozenset[str] = frozenset({"txt", "lst", "list", "dic", "dict"})


def _looks_like_wordlist(value: str) -> bool:
    # a relative wordlist path may not resolve from the interpreter's cwd (netexec runs with the
    # profile dir as cwd), so Path.is_file() alone misses `-p pass.txt`. A known wordlist extension
    # is a strong file signal a single interactive password (`-p sa`, `-p ''`) never has.
    return value.rsplit("/", 1)[-1].rsplit(".", 1)[-1].lower() in _WORDLIST_EXTS


def _netexec_violation(argv: list[str]) -> str | None:
    i = 1
    while i < len(argv):
        token = argv[i]
        flag, sep, inline = token.partition("=")
        if sep and flag in _NETEXEC_AUTH_FLAGS:  # `-p=X` / `--password=X`
            values = [inline]
            i += 1
        elif sep:
            # a non-auth `KEY=value` netexec module option (`-o OUT=x.txt`) is not a credential, so
            # don't evaluate its value for spray/brute — doing so was a false block (bug #19).
            i += 1
            continue
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
        # count the raw nargs run, NOT the empty-filtered list: `-u '' admin` is a 2-username spray,
        # but filtering the '' first left len==1 and slipped a multi-cred spray past the guard. A
        # legit Tier-2 single default-cred (`-u administrator -p ''`) is still one value per flag.
        if len(values) > 1:
            return f"netexec {flag} has {len(values)} inline credentials — spray (forbidden)"
        for value in values:
            if value and (Path(value).is_file() or _looks_like_wordlist(value)):
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


def policy_violation(argv: list[str], *, spray: bool = False, exploit: bool = False) -> str | None:
    # `spray=True` ONLY in opt-in Spray mode (§2a); `exploit=True` ONLY for a command the user
    # SELECTED and CONFIRMED in the Exploitation tab (§2b).
    #
    # Exploitation mode is a human-driven attack console: the operator picks the command + confirms
    # it against a named target before anything runs. That human step — not a tool block-list — is
    # the guardrail (OSCP bans *auto*-exploitation + AI, not manual attack scripts; nothing here is
    # automatic or chained). So exploit mode runs the confirmed command as-is, including attack
    # tools recon mode would never allow. The DEFAULT recon mode is unchanged and stays exam-legal.
    if not argv:
        return "empty command"
    if exploit:
        return None  # user-selected + confirmed attack command — the human is the gate
    # --- recon / spray (default, exam-legal) below ---
    tool = argv[0]
    base = os.path.basename(tool).lower()
    allowed = set(ALLOWED_TOOLS)
    if spray:
        allowed |= SPRAY_TOOLS
    if tool not in allowed and base not in allowed:
        return f"{tool} is not on the OSCP-allowed tool list"
    if not spray:
        for token in argv[1:]:
            head = token.split("=", 1)[0].lower()  # catch --passwords=FILE, not just --passwords
            if head in _FORBIDDEN_FLAGS:
                return (
                    f"{head} is a credential brute/spray flag (off by default — enable Spray mode)"
                )
    # why: drive EVERY per-tool sub-check off `base` (the lowercased basename), NOT the raw argv[0].
    # An absolute/relative path (/usr/bin/netexec, ./nmap) passes the allow-list via `base` but
    # slip past a `tool == "netexec"` check, letting list-driven spray / brute run in recon mode.
    if base == "nmap" and not spray:
        for value in _script_values(argv):
            for script in value.split(","):  # --script takes a comma list; judge each name
                name = script.strip().lower()
                # `all` / `*` run EVERY script incl. the *-brute credential scripts, but carry no
                # literal "brute" substring for the per-name check — block the glob-everything form
                if name in ("all", "*"):
                    return "nmap --script all/* runs credential brute (off by default — Spray mode)"
                if "brute" in name and name not in _NMAP_RECON_BRUTE:
                    return f"nmap --script {name} is credential brute (off by default — Spray mode)"
    if base == "searchsploit":
        for token in argv[1:]:
            if token in _SEARCHSPLOIT_FORBIDDEN:
                return f"searchsploit {token} is not display-only (forbidden)"
    if base == "aws":
        aws_violation = _aws_violation(argv)
        if aws_violation is not None:
            return aws_violation
    if base == "wpscan" and not spray:
        for token in argv[1:]:
            head = token.split("=", 1)[0]  # --passwords=FILE / --usernames=FILE
            # `-Pfile` / `-Ufile` concatenated short form (wpscan's Ruby OptionParser accepts it)
            concat = (
                len(token) > 2 and not token.startswith("--") and token[:2] in _WPSCAN_FORBIDDEN
            )
            if head in _WPSCAN_FORBIDDEN or concat:
                flag = token[:2] if concat else head
                return f"wpscan {flag} is credential brute (off by default — enable Spray mode)"
    if base in _NETEXEC_TOOLS and not spray:
        netexec_violation = _netexec_violation(argv)
        if netexec_violation is not None:
            return netexec_violation
    if base == "ike-scan":
        ike_violation = _ike_scan_violation(argv)
        if ike_violation is not None:
            return ike_violation
    if base == "ntpdate" and "-q" not in argv[1:]:
        # why: ntpdate WITHOUT -q SETS the local clock (modifies local state, needs root). Recon is
        # query-only — the module always passes -q; back-stop it here for the custom-command path.
        return "ntpdate without -q sets the local clock (forbidden — recon-only)"
    if base in _DB_CLIENTS and not exploit:
        # the DB file/OS primitives (INTO OUTFILE, xp_cmdshell, load_file…) are BLOCKED in recon
        # (query-only), but they ARE the attack in Exploitation mode — permit them there (user opted
        # in + confirmed). The hard-forbidden block above still applies.
        db_violation = _db_primitive_violation(base, argv)
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
    exploit: bool = False,
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

    violation = policy_violation(argv, spray=spray, exploit=exploit)
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

    # exploit mode is the user's own attack console — log the raw command (they want to see it);
    # recon commands stay redacted in the diagnostics log as before.
    logger.info("run: %s", shell_line if exploit else redacted)
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
