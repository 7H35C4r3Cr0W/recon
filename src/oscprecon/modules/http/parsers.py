from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit


@dataclass
class HttpFinding:
    port: int
    path: str
    status: int
    size: int = 0
    redirect_to: str = ""
    note: str = ""
    module: str = "http"

    def to_dict(self, discovered_at: str) -> dict[str, Any]:
        return {
            "module": self.module,
            "port": self.port,
            "path": self.path,
            "status": self.status,
            "size": self.size,
            "redirect_to": self.redirect_to,
            "note": self.note,
            "discovered_at": discovered_at,
        }


def _path_of(url: str) -> str:
    return urlsplit(url).path or "/"


_SIZE_UNITS = (("KB", 1024), ("MB", 1024 * 1024), ("GB", 1024 * 1024 * 1024), ("B", 1))


def _parse_size(token: str) -> int:
    text = token.strip().upper()
    for unit, factor in _SIZE_UNITS:
        if text.endswith(unit):
            try:
                return int(float(text[: -len(unit)].strip()) * factor)
            except ValueError:
                return 0
    try:
        return int(text)
    except ValueError:
        return 0


# feroxbuster plain -o line: "301  GET  8l  22w  154c  http://x/admin => /admin/"
_FEROX_PLAIN = re.compile(
    r"^(?P<status>\d{3})\s+\w+\s+\d+l\s+\d+w\s+(?P<size>\d+)c\s+(?P<url>\S+)"
    r"(?:\s+=>\s+(?P<redir>\S+))?"
)


def parse_feroxbuster(text: str, port: int) -> list[HttpFinding]:
    findings: list[HttpFinding] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("{"):  # --json ndjson line
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict) or obj.get("type") != "response":
                continue
            headers = obj.get("headers", {})
            redirect = str(headers.get("location", "")) if isinstance(headers, dict) else ""
            findings.append(
                HttpFinding(
                    port=port,
                    path=_path_of(str(obj.get("url", ""))),
                    status=int(obj.get("status", 0) or 0),
                    size=int(obj.get("content_length", 0) or 0),
                    redirect_to=redirect,
                )
            )
            continue
        match = _FEROX_PLAIN.match(line)  # default plain -o output (the §9 reference form)
        if match is not None:
            findings.append(
                HttpFinding(
                    port=port,
                    path=_path_of(match.group("url")),
                    status=int(match.group("status")),
                    size=int(match.group("size")),
                    redirect_to=(match.group("redir") or ""),
                )
            )
    return findings


_GOBUSTER = re.compile(
    r"^(?P<path>/\S*)\s+\(Status:\s*(?P<status>\d+)\)\s+\[Size:\s*(?P<size>\d+)\]"
    r"(?:\s+\[-->\s*(?P<redir>[^\]]+)\])?"
)


def parse_gobuster(text: str, port: int) -> list[HttpFinding]:
    findings: list[HttpFinding] = []
    for line in text.splitlines():
        match = _GOBUSTER.match(line.strip())
        if match is None:
            continue
        findings.append(
            HttpFinding(
                port=port,
                path=match.group("path"),
                status=int(match.group("status")),
                size=int(match.group("size")),
                redirect_to=(match.group("redir") or "").strip(),
            )
        )
    return findings


def parse_ffuf(text: str, port: int) -> list[HttpFinding]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    results = data.get("results", [])
    findings: list[HttpFinding] = []
    if not isinstance(results, list):
        return findings
    for result in results:
        if not isinstance(result, dict):
            continue
        findings.append(
            HttpFinding(
                port=port,
                path=_path_of(str(result.get("url", ""))),
                status=int(result.get("status", 0) or 0),
                size=int(result.get("length", 0) or 0),
                redirect_to=str(result.get("redirectlocation", "") or ""),
            )
        )
    return findings


_DIRSEARCH = re.compile(
    r"^\[\d\d:\d\d:\d\d\]\s+(?P<status>\d{3})\s+-\s+(?P<size>\S+)\s+-\s+(?P<path>/\S*)"
    r"(?:\s+->\s+(?P<redir>\S+))?"
)


def parse_dirsearch(text: str, port: int) -> list[HttpFinding]:
    findings: list[HttpFinding] = []
    for line in text.splitlines():
        match = _DIRSEARCH.match(line.strip())
        if match is None:
            continue
        findings.append(
            HttpFinding(
                port=port,
                path=match.group("path"),
                status=int(match.group("status")),
                size=_parse_size(match.group("size")),
                redirect_to=(match.group("redir") or ""),
            )
        )
    return findings


_NIKTO_OSVDB = re.compile(r"^OSVDB-\d+:\s*(.*)$")


def parse_nikto(text: str, port: int) -> list[HttpFinding]:
    findings: list[HttpFinding] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("+ "):
            continue
        message = stripped[2:].strip()
        # a real path finding starts with '/...' (optionally after an 'OSVDB-####:' prefix);
        # banner/version lines like 'Server: Apache/2.4.41' are notes, not a '/2.4.41' path.
        candidate = message
        osvdb = _NIKTO_OSVDB.match(candidate)
        if osvdb is not None:
            candidate = osvdb.group(1).strip()
        path = candidate.split()[0].rstrip(":") if candidate.startswith("/") else "/"
        findings.append(HttpFinding(port=port, path=path, status=0, note=message))
    return findings


def parse_whatweb(text: str, port: int) -> list[HttpFinding]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    entries = data if isinstance(data, list) else [data]
    findings: list[HttpFinding] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        plugins = entry.get("plugins", {})
        names = ", ".join(sorted(plugins)) if isinstance(plugins, dict) else ""
        findings.append(
            HttpFinding(
                port=port,
                path=_path_of(str(entry.get("target", ""))),
                status=int(entry.get("http_status", 0) or 0),
                note=f"whatweb: {names}" if names else "whatweb",
            )
        )
    return findings


def parse_wpscan(text: str, port: int) -> list[HttpFinding]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    findings: list[HttpFinding] = []
    version = data.get("version")
    if isinstance(version, dict) and version.get("number"):
        findings.append(HttpFinding(port, "/", 0, note=f"WordPress {version['number']}"))
    plugins = data.get("plugins")
    if isinstance(plugins, dict):
        for name in plugins:
            findings.append(
                HttpFinding(port, f"/wp-content/plugins/{name}/", 0, note=f"plugin: {name}")
            )
    users = data.get("users")
    if isinstance(users, dict) and users:
        findings.append(HttpFinding(port, "/", 0, note=f"users: {', '.join(users)}"))
    return findings


_PARSERS = {
    "feroxbuster": parse_feroxbuster,
    "gobuster": parse_gobuster,
    "ffuf": parse_ffuf,
    "dirsearch": parse_dirsearch,
    "nikto": parse_nikto,
    "whatweb": parse_whatweb,
    "wpscan": parse_wpscan,
}


def parse_tool(tool: str, text: str, port: int) -> list[HttpFinding]:
    parser = _PARSERS.get(tool)
    return parser(text, port) if parser is not None else []


def detect_wordpress(*texts: str) -> bool:
    blob = " ".join(texts).lower()
    return "wordpress" in blob or "wp-content" in blob or "wp-login" in blob
