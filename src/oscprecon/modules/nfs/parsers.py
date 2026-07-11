from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

# A client token that means "any host on the internet" — an export shared to one of these is
# mountable anonymously (§12 world-readable). A restricted token like 10.0.0.0/24 or *.corp.local
# is NOT world-readable, so the match is exact, not a substring on '*'.
_WORLD_CLIENTS = frozenset({"*", "(everyone)", "everyone", "0.0.0.0/0"})

# Filenames worth calling out when they surface in an NFS listing — SSH keys / password stores /
# VPN configs commonly hand over a foothold. Substring match (case-insensitive).
_SECRET_HINTS = (
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "authorized_keys",
    ".ssh",
    "shadow",
    "passwd",
    ".kdbx",
    ".ovpn",
    "credential",
    ".bash_history",
)


@dataclass
class NfsFinding:
    kind: str  # export | world-readable | access | file | banner | note
    value: str
    detail: str = ""
    module: str = "nfs"

    def to_dict(self, discovered_at: str) -> dict[str, Any]:
        return {
            "module": self.module,
            "kind": self.kind,
            "value": self.value,
            "detail": self.detail,
            "discovered_at": discovered_at,
        }


def _world_readable(clients: str) -> bool:
    tokens = [t for t in re.split(r"[,\s]+", clients.strip()) if t]
    return any(t.lower() in _WORLD_CLIENTS for t in tokens)


def is_secret_name(name: str) -> bool:
    low = name.lower()
    return any(hint in low for hint in _SECRET_HINTS)


def _export_findings(line: str) -> list[NfsFinding]:
    # An export line is `PATH   client[,client...]`; the path is the first field, the client ACL is
    # the remainder (kept verbatim so a comma/space-joined list survives). Paths with spaces are not
    # representable here (as with every showmount parser) — NFS export paths don't use them.
    parts = line.split(None, 1)
    path = parts[0]
    clients = parts[1].strip() if len(parts) > 1 else ""
    out = [NfsFinding("export", path, f"clients: {clients}" if clients else "")]
    if _world_readable(clients):
        out.append(NfsFinding("world-readable", path, f"exported to {clients or 'everyone'}"))
    return out


def parse_showmount(text: str) -> list[NfsFinding]:
    findings: list[NfsFinding] = []
    for raw in text.splitlines():
        line = raw.strip()
        # An export path is absolute, so a leading '/' cleanly selects export rows and skips the
        # "Export list for HOST:" header, RPC errors (clnt_create: ...) and [missing]/[blocked].
        if line.startswith("/"):
            findings.extend(_export_findings(line))
    return findings


_NFS_VER = re.compile(r"^\d+/tcp\s+open\s+nfs[\w-]*\s+(?P<ver>\S.*)$", re.MULTILINE)
# nfs-ls row: PERMISSION UID GID SIZE TIME FILENAME. TIME is `YYYY-MM-DD[T ]HH:MM[:SS]`; the name is
# the remainder (internal spaces preserved). PERMISSION is an optional type char + 9 mode chars.
_NFS_FILE = re.compile(
    r"^(?P<perm>[dlbcps-]?[rwxsStT-]{9})\s+\d+\s+\d+\s+\d+\s+"
    r"\d{4}-\d\d-\d\d[T ]\d\d:\d\d(?::\d\d)?\s+(?P<name>\S.*?)\s*$"
)
_NMAP_BOUNDARY = ("PORT", "Service Info", "Nmap done", "Nmap scan report", "Host is", "MAC Address")


def parse_nmap_nfs(text: str) -> list[NfsFinding]:
    findings: list[NfsFinding] = []
    version = _NFS_VER.search(text)
    if version is not None:
        findings.append(NfsFinding("banner", version.group("ver").strip()))
    section = ""  # showmount | ls | statfs
    volume = ""
    for raw in text.splitlines():
        line = re.sub(r"^\|[_ ]?", "", raw).rstrip()  # strip nmap's "| "/"|_" script prefix
        stripped = line.strip()
        low = stripped.lower()
        if low.startswith("nfs-showmount:"):
            section = "showmount"
            continue
        if low.startswith("nfs-ls:"):
            section = "ls"
            match = re.search(r"Volume\s+(?P<vol>/\S+)", stripped)
            volume = match.group("vol") if match is not None else ""
            continue
        if low.startswith("nfs-statfs:"):
            section = "statfs"
            continue
        if re.match(r"\d+/\w+\s+(open|closed|filtered)\b", stripped) or stripped.startswith(
            _NMAP_BOUNDARY
        ):
            section = ""  # a top-level nmap line ends the current script block
            continue
        if not stripped:
            continue
        if section == "showmount" and stripped.startswith("/"):
            findings.extend(_export_findings(stripped))
        elif section == "ls":
            if low.startswith("access:"):
                caps = stripped.split(":", 1)[1].strip()
                # tokens are "Read"/"NoModify"/"Modify"/... — a standalone "Modify" means writable;
                # "NoModify" is one word so \bModify\b does not match inside it.
                writable = bool(re.search(r"\bModify\b", caps))
                state = "writable" if writable else "read-only"
                findings.append(
                    NfsFinding("access", volume or "?", f"{state} ({caps})" if caps else state)
                )
            else:
                file_match = _NFS_FILE.match(stripped)
                if file_match is not None:
                    name = file_match.group("name")
                    if name not in (".", ".."):
                        findings.append(
                            NfsFinding("file", name, f"{file_match.group('perm')} in {volume}")
                        )
    return findings


_PARSERS = {
    "showmount": parse_showmount,
    "nmap-nfs": parse_nmap_nfs,
}


def parse_nfs_tool(tool: str, text: str) -> list[NfsFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
