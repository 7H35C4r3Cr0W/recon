from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class SmbEntry:
    name: str
    is_dir: bool
    size: int = 0


# smbclient `ls`: "  <name>  <attrs>  <size>  <DOW> <Mon> <DD> <HH:MM:SS> <YYYY>". Anchor on the
# trailing date so a name with spaces survives; attrs is a letter combo (D=dir, A/N/H/R/S/L).
_SMB_LS = re.compile(
    r"^\s+(?P<name>.*\S)\s+(?P<attrs>[DAHRSNL]+)\s+(?P<size>\d+)\s+"
    r"\w{3}\s+\w{3}\s+\d+\s+[\d:]+\s+\d{4}\s*$"
)
# lines smbclient interleaves with a streamed file's content (`get file -`), plus its banners
_SMB_NOISE = re.compile(r"^(getting file |NT_STATUS|\s*\d+ blocks of size|Domain=|OS=|Try \"help)")


def parse_smbclient_ls(text: str) -> list[SmbEntry]:
    entries: list[SmbEntry] = []
    for line in text.splitlines():
        match = _SMB_LS.match(line.rstrip())
        if match is None:
            continue
        name = match.group("name").strip()
        if name in (".", ".."):
            continue
        is_dir = "D" in match.group("attrs")
        entries.append(SmbEntry(name, is_dir, 0 if is_dir else int(match.group("size"))))
    return entries


def strip_smbclient_noise(text: str) -> str:
    # drop smbclient's status/banner lines so a peek shows the FILE, not the tool chatter
    return "\n".join(line for line in text.splitlines() if not _SMB_NOISE.match(line))


@dataclass
class SmbFinding:
    kind: str  # auth | signing | share | user | policy | note | peek
    value: str
    detail: str = ""
    module: str = "smb"

    def to_dict(self, discovered_at: str) -> dict[str, Any]:
        return {
            "module": self.module,
            "kind": self.kind,
            "value": self.value,
            "detail": self.detail,
            "discovered_at": discovered_at,
        }


# netexec lines are prefixed "SMB <host> <port> <NAME>  <rest>"; strip that to reach the content.
_NXC_PREFIX = re.compile(r"^SMB\s+\S+\s+\d+\s+\S+\s+(?P<rest>.*)$")


def _nxc_rest(line: str) -> str | None:
    match = _NXC_PREFIX.match(line)
    return match.group("rest").rstrip() if match is not None else None


def netexec_auth_ok(text: str) -> bool:
    for line in text.splitlines():
        rest = _nxc_rest(line)
        if rest is not None and rest.startswith("[+]"):
            return True
    return False


def parse_netexec_shares(text: str) -> list[SmbFinding]:
    findings: list[SmbFinding] = []
    in_table = False
    perm_start = perm_end = -1  # header column offsets of the Permissions cell (fixed-width table)
    for line in text.splitlines():
        rest = _nxc_rest(line)
        if rest is None:
            continue
        signing = re.search(r"signing:(True|False)", rest)
        if signing is not None:
            findings.append(
                SmbFinding("signing", "enabled" if signing.group(1) == "True" else "disabled")
            )
        if rest.startswith("[+]"):
            findings.append(SmbFinding("auth", "authenticated", rest[3:].strip()))
            continue
        if rest.startswith("Share") and "Permissions" in rest:
            in_table = True
            # capture the fixed-width Permissions column span so an EMPTY perms cell can't pull the
            # Remark text ("READ" as a bare remark) in as a fake permission (share-perms bug #45).
            perm_start = rest.index("Permissions")
            perm_end = rest.index("Remark") if "Remark" in rest else len(rest)
            continue
        if rest.startswith("---"):
            continue
        if in_table:
            if rest.startswith("["):
                in_table = False
                continue
            # netexec pads columns, so split on 2+ spaces: a multi-word share name (single spaces)
            # stays intact.
            cols = re.split(r"\s{2,}", rest.strip())
            if not cols or not cols[0]:
                in_table = False
                continue
            # read perms ONLY from the Permissions column span (not every column after the name), so
            # a Remark where perms would be won't false-flag the share readable/writable. If a long
            # share name overflows the column, fall back to the old comma-token scan of cols[1].
            if perm_start >= 0 and len(cols[0]) <= perm_start:
                cell = rest[perm_start:perm_end]
            else:
                cell = cols[1] if len(cols) >= 2 else ""
            perms = [p for p in re.split(r"[,\s]+", cell.strip()) if p in ("READ", "WRITE")]
            findings.append(SmbFinding("share", cols[0], ",".join(perms)))
    return findings


_DOMAIN_USER = re.compile(r"^[^\\\s]+\\(?P<user>\S+)")


def parse_netexec_users(text: str) -> list[SmbFinding]:
    # netexec 1.4.0 prints --users as a fixed-width table with NO domain prefix and a
    # "-Username- -Last PW Set- -BadPW- -Description-" header; the username is the first column.
    # Older CME-style "DOMAIN\\user" lines are still handled via the backslash fallback.
    findings: list[SmbFinding] = []
    for line in text.splitlines():
        rest = _nxc_rest(line)
        if rest is None:
            continue
        rest = rest.strip()
        if not rest or rest.startswith("[") or rest.startswith("-Username-"):
            continue
        match = _DOMAIN_USER.match(rest)
        if match is not None:
            findings.append(SmbFinding("user", match.group("user")))
            continue
        findings.append(SmbFinding("user", rest.split()[0]))
    return findings


_RID_USER = re.compile(r"^\d+:\s+\S+\\(?P<name>.+?)\s+\(SidTypeUser\)")


def parse_netexec_ridbrute(text: str) -> list[SmbFinding]:
    findings: list[SmbFinding] = []
    for line in text.splitlines():
        rest = _nxc_rest(line)
        if rest is None:
            continue
        match = _RID_USER.match(rest)
        if match is not None:
            findings.append(SmbFinding("user", match.group("name"), "rid-brute"))
    return findings


def parse_netexec_passpol(text: str) -> list[SmbFinding]:
    findings: list[SmbFinding] = []
    for line in text.splitlines():
        rest = _nxc_rest(line)
        if rest is None or rest.startswith("[") or ":" not in rest:
            continue
        key, _, value = rest.partition(":")
        key = key.strip()
        if key.lower() in (
            "minimum password length",
            "password history length",
            "account lockout threshold",
            "maximum password age",
        ):
            findings.append(SmbFinding("policy", key, value.strip()))
    return findings


# smbclient -L share row: "<name>  <Type>  [comment]" where Type is Disk/IPC/Printer. Its trailing
# status prose ("Reconnecting with SMB1 ...", "Unable to connect ...") has no Type column, so it
# must not be mistaken for a share name when smbclient omits the usual blank line before it.
_SHARE_TYPES = {"Disk", "IPC", "Printer", "Device"}


def parse_smbclient_shares(text: str) -> list[SmbFinding]:
    findings: list[SmbFinding] = []
    in_table = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("Sharename"):
            in_table = True
            continue
        if stripped.startswith("---"):
            continue
        if in_table:
            if not stripped or stripped.startswith("SMB1") or stripped.startswith("Server"):
                in_table = False
                continue
            cols = re.split(r"\s{2,}", stripped)  # 2+ spaces: keep multi-word share names intact
            if len(cols) >= 2 and cols[1] in _SHARE_TYPES and cols[0]:
                findings.append(SmbFinding("share", cols[0]))
    return findings


_RPC_USER = re.compile(r"user:\[(?P<name>[^\]]+)\]")


def parse_rpcclient_users(text: str) -> list[SmbFinding]:
    findings: list[SmbFinding] = []
    for line in text.splitlines():
        match = _RPC_USER.search(line)
        if match is not None:
            findings.append(SmbFinding("user", match.group("name")))
    return findings


_PARSERS = {
    "netexec-shares": parse_netexec_shares,
    "netexec-users": parse_netexec_users,
    "netexec-ridbrute": parse_netexec_ridbrute,
    "netexec-passpol": parse_netexec_passpol,
    "smbclient-shares": parse_smbclient_shares,
    "rpcclient-users": parse_rpcclient_users,
}


def parse_smb_tool(tool: str, text: str) -> list[SmbFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []


def readable_shares(findings: list[SmbFinding]) -> list[str]:
    return [f.value for f in findings if f.kind == "share" and "READ" in f.detail]


def writable_shares(findings: list[SmbFinding]) -> list[str]:
    # a guest/anon-WRITABLE share is a real exposure (upload / print-job / wide-link write vector),
    # surfaced distinctly from a merely-readable one (HTB Abducted: guest-writable printer share).
    return [f.value for f in findings if f.kind == "share" and "WRITE" in f.detail]


def dedup_share_findings(findings: list[SmbFinding]) -> list[SmbFinding]:
    # the same share is listed by two enum methods — `smbclient -L` (name only, no perms) and
    # `netexec --shares` (name + READ/WRITE) — so a share otherwise appears twice, once blank and
    # once with its access. Collapse by name, unioning the access tokens so the WRITE/READ a single
    # method saw is never lost and the graph/report shows one node per share.
    access: dict[str, set[str]] = {}
    order: list[str] = []
    others: list[SmbFinding] = []
    for f in findings:
        if f.kind != "share":
            others.append(f)
            continue
        if f.value not in access:
            access[f.value] = set()
            order.append(f.value)
        access[f.value].update(t for t in re.split(r"[,\s]+", f.detail) if t in ("READ", "WRITE"))
    merged = [
        SmbFinding("share", name, ",".join(t for t in ("READ", "WRITE") if t in access[name]))
        for name in order
    ]
    return others + merged
