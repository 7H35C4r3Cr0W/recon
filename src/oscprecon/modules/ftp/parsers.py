from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class FtpFinding:
    kind: str  # auth | banner | dir | file | note
    value: str
    detail: str = ""
    module: str = "ftp"

    def to_dict(self, discovered_at: str) -> dict[str, Any]:
        return {
            "module": self.module,
            "kind": self.kind,
            "value": self.value,
            "detail": self.detail,
            "discovered_at": discovered_at,
        }


@dataclass
class FtpEntry:
    name: str
    is_dir: bool
    size: int = 0


# Unix `ls -l`: perms, links, owner, group, size, month, day, time/year, then the name. The name is
# captured verbatim (a filename may contain 2+ consecutive spaces), so match the 8 fixed fields
# positionally rather than split() (which would collapse runs of whitespace inside the name).
_UNIX_LINE = re.compile(
    r"^(?P<perms>[-dlbcps][rwxsStT-]{9}[.+@]?)\s+"
    r"\S+\s+\S+\s+\S+\s+"  # links owner group
    r"(?P<size>\d+)\s+"  # size
    r"\S+\s+\S+\s+\S+\s+"  # month day time/year
    r"(?P<name>.+)$"
)
# MS-DOS / IIS listing: "06-20-23  10:12AM       <DIR>          uploads".
_DOS_LINE = re.compile(
    r"^(?P<date>\d{2}-\d{2}-\d{2,4})\s+(?P<time>\d{1,2}:\d{2}(?:AM|PM)?)\s+"
    r"(?P<sizeordir><DIR>|\d+)\s+(?P<name>.+?)\s*$"
)


def _parse_unix(line: str) -> FtpEntry | None:
    match = _UNIX_LINE.match(line)
    if match is None:
        return None
    perms = match.group("perms")
    is_dir = perms[0] == "d"
    name = match.group("name")
    if perms[0] == "l" and " -> " in name:  # symlink: keep the link name, drop the target
        name = name.split(" -> ", 1)[0]
    return FtpEntry(name, is_dir, 0 if is_dir else int(match.group("size")))


def parse_ftp_listing(text: str) -> list[FtpEntry]:
    entries: list[FtpEntry] = []
    for raw in text.splitlines():
        line = raw.rstrip("\r\n")  # keep internal + trailing spaces in the name; drop only the EOL
        if not line.strip():
            continue
        entry = _parse_unix(line.lstrip())  # lstrip leading indent; name keeps its own spaces
        if entry is None:
            match = _DOS_LINE.match(line.strip())
            if match is None:
                continue
            is_dir = match.group("sizeordir") == "<DIR>"
            size = 0 if is_dir else int(match.group("sizeordir"))
            entry = FtpEntry(match.group("name").strip(), is_dir, size)
        if entry.name in (".", ".."):
            continue
        entries.append(entry)
    return entries


def _listing_findings(text: str, base: str = "/") -> list[FtpFinding]:
    findings: list[FtpFinding] = []
    prefix = base if base.endswith("/") else base + "/"
    for entry in parse_ftp_listing(text):
        path = prefix + entry.name
        kind = "dir" if entry.is_dir else "file"
        detail = "" if entry.is_dir else f"{entry.size} bytes"
        findings.append(FtpFinding(kind, path, detail))
    return findings


def parse_curl_list(text: str) -> list[FtpFinding]:
    return _listing_findings(text, "/")


_NMAP_VER = re.compile(r"^\d+/tcp\s+open\s+ftp[-\w]*\s+(?P<ver>\S.*)$", re.MULTILINE)


def nmap_anon_ok(text: str) -> bool:
    return "Anonymous FTP login allowed" in text


def parse_nmap_ftp(text: str) -> list[FtpFinding]:
    findings: list[FtpFinding] = []
    if nmap_anon_ok(text):
        findings.append(FtpFinding("auth", "anonymous", "Anonymous FTP login allowed"))
    version = _NMAP_VER.search(text)
    if version is not None:
        findings.append(FtpFinding("banner", version.group("ver").strip()))
    if "bounce working" in text.lower():
        findings.append(
            FtpFinding("note", "ftp-bounce", "FTP bounce accepted (PORT to a third party)")
        )
    # ftp-anon prints the root listing prefixed with "| " / "|_" and appends " [NSE: writeable]" to
    # any world-writable entry. Strip both — otherwise the marker is folded into the file/dir name —
    # but keep the writable signal as a note (anonymous-writable dirs are a notable recon finding).
    cleaned: list[str] = []
    for raw in text.splitlines():
        line = re.sub(r"^\|[_ ]?", "", raw)
        if "[NSE: writeable]" in line:
            without = re.sub(r"\s*\[NSE: writeable\]\s*$", "", line)
            entries = parse_ftp_listing(without)
            if entries:
                findings.append(
                    FtpFinding("note", f"writable: /{entries[0].name}", "anonymous write allowed")
                )
            line = without
        cleaned.append(line)
    findings.extend(_listing_findings("\n".join(cleaned), "/"))
    return findings


_PARSERS = {
    "nmap-ftp": parse_nmap_ftp,
    "curl-list": parse_curl_list,
}


def parse_ftp_tool(tool: str, text: str) -> list[FtpFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []


def subdirs(text: str) -> list[str]:
    return [e.name for e in parse_ftp_listing(text) if e.is_dir]
