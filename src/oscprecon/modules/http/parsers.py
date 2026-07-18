from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _clean(text: str) -> str:
    # why: tool output can carry ANSI/control bytes (progress redraws, a truncated write). Strip
    # them from every string field so they never leak into findings.json, reports, or GUI text.
    return _CONTROL_RE.sub("", text)


@dataclass
class HttpFinding:
    port: int
    path: str
    status: int
    size: int = 0
    redirect_to: str = ""
    note: str = ""
    module: str = "http"
    method: str = ""  # HTTP verb from the dir-buster (GET/POST) — for the Discovered URLs table
    lines: int = 0  # response line count (feroxbuster -o "8l")
    words: int = 0  # response word count (feroxbuster -o "22w")

    def __post_init__(self) -> None:
        self.path = _clean(self.path)
        self.redirect_to = _clean(self.redirect_to)
        self.note = _clean(self.note)
        self.method = _clean(self.method)

    def to_dict(self, discovered_at: str) -> dict[str, Any]:
        return {
            "module": self.module,
            "port": self.port,
            "path": self.path,
            "status": self.status,
            "size": self.size,
            "redirect_to": self.redirect_to,
            "note": self.note,
            "method": self.method,
            "lines": self.lines,
            "words": self.words,
            "discovered_at": discovered_at,
        }


def _path_of(url: str) -> str:
    return urlsplit(url).path or "/"


_SIZE_UNITS = (("KB", 1024), ("MB", 1024 * 1024), ("GB", 1024 * 1024 * 1024), ("B", 1))


def _to_int(value: object) -> int:
    # why: JSON-derived numeric fields (ffuf/gobuster --json) can drift to a non-numeric type on a
    # tool update — never let int() raise; a bad value degrades to 0, not a crash (tool-resilience).
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return 0
    return 0


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
    r"^(?P<status>\d{3})\s+(?P<method>\w+)\s+(?P<lines>\d+)l\s+(?P<words>\d+)w\s+"
    r"(?P<size>\d+)c\s+(?P<url>\S+)(?:\s+=>\s+(?P<redir>\S+))?"
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
                    status=_to_int(obj.get("status", 0)),
                    size=_to_int(obj.get("content_length", 0)),
                    redirect_to=redirect,
                    method=str(obj.get("method", "") or ""),
                    lines=_to_int(obj.get("line_count", 0)),
                    words=_to_int(obj.get("word_count", 0)),
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
                    method=match.group("method"),
                    lines=int(match.group("lines")),
                    words=int(match.group("words")),
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
                status=_to_int(result.get("status", 0)),
                size=_to_int(result.get("length", 0)),
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


def _parse_whatweb_json(text: str, port: int) -> list[HttpFinding]:
    # whatweb --log-json drifts between a single JSON array/object and NDJSON (one object per line)
    # across versions. Try the whole doc first, then fall back to line-by-line, skipping bad rows —
    # so a format change or one malformed line never drops the rest.
    stripped = text.strip()
    entries: list[Any] = []
    try:
        data = json.loads(stripped)
        entries = data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        for line in stripped.splitlines():
            candidate = line.strip()
            if not candidate:
                continue
            try:
                entries.append(json.loads(candidate))
            except json.JSONDecodeError:
                continue
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
                status=_to_int(entry.get("http_status", 0)),
                note=f"whatweb: {names}" if names else "whatweb",
            )
        )
    return findings


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
# plain summary line: "http://host/ [200 OK] Apache[2.4.38], JQuery[3.2.1], PasswordField[password]"
_WHATWEB_PLAIN = re.compile(r"^(?P<url>\S+)\s+\[(?P<status>\d{3})[^\]]*\]\s+(?P<plugins>.+)$")

# whatweb plugins that carry a redirect target; a redirect to a *hostname* (not the target IP) is a
# vhost worth enumerating — surface it so the operator adds it to /etc/hosts (§10 vhost module).
_REDIRECT_PLUGINS = frozenset({"meta-refresh-redirect", "redirectlocation", "location"})
# a real vhost name: has a letter and a dotted TLD, so a bare IP ("10.10.10.5") is rejected.
_VHOST_HOST_RE = re.compile(r"^(?=.*[A-Za-z])[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


def _split_top_level(text: str) -> list[str]:
    # split on commas that are NOT inside [...] — a whatweb plugin detail (e.g. a page Title) can
    # itself carry commas, so a naive split would shred the plugin names.
    parts: list[str] = []
    depth = 0
    start = 0
    for i, ch in enumerate(text):
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            parts.append(text[start:i])
            start = i + 1
    parts.append(text[start:])
    return [p.strip() for p in parts if p.strip()]


def _plugin_name_value(seg: str) -> tuple[str, str]:
    name, sep, rest = seg.partition("[")
    value = rest[:-1] if sep and rest.endswith("]") else ""
    return name.strip(), value.strip()


def is_vhost_host(value: str) -> bool:
    return bool(_VHOST_HOST_RE.match(value.strip()))


def vhost_from_redirect(value: str) -> str:
    # pull a vhost hostname out of a redirect target ("http://unika.htb/" -> "unika.htb"); return it
    # only when it looks like a real vhost name (has a dotted TLD + a letter, not a bare IP).
    target = value.strip()
    host = urlsplit(target if "//" in target else f"//{target}").hostname or ""
    return host if is_vhost_host(host) else ""


def _redirect_findings(
    pairs: list[tuple[str, str]], port: int, path: str, status: int
) -> list[HttpFinding]:
    out: list[HttpFinding] = []
    seen: set[str] = set()
    for name, value in pairs:
        if name.lower() not in _REDIRECT_PLUGINS:
            continue
        host = vhost_from_redirect(value)
        if host and host not in seen:
            seen.add(host)
            out.append(
                HttpFinding(
                    port=port,
                    path=path,
                    status=status,
                    redirect_to=host,
                    note=f"redirect -> {host} — add to /etc/hosts and enumerate as a vhost",
                )
            )
    return out


# whatweb plugins whose VALUE is noise, not signal — the value is dropped, the name kept. Country is
# always RESERVED/ZZ for lab IPs; IP just echoes the target we already know.
_NOISE_VALUE_PLUGINS = frozenset({"country", "ip"})


def _render_plugins(pairs: list[tuple[str, str]]) -> str:
    # keep the plugin VALUES — the real recon signal (Title[UniFi Network],
    # HTTPServer[Apache/2.4.38], X-Powered-By[PHP/7.4]) — instead of collapsing every plugin to a
    # bare name. Preserves whatweb's order, dedupes, and bounds the length so a plugin-heavy page
    # can't produce a runaway note.
    parts: list[str] = []
    seen: set[str] = set()
    for name, value in pairs:
        if not name:
            continue
        seg = f"{name}[{value}]" if value and name.lower() not in _NOISE_VALUE_PLUGINS else name
        if seg not in seen:
            seen.add(seg)
            parts.append(seg)
    rendered = ", ".join(parts)
    return rendered[:299] + "…" if len(rendered) > 300 else rendered


def _parse_whatweb_plain(text: str, port: int) -> list[HttpFinding]:
    findings: list[HttpFinding] = []
    for raw in text.splitlines():
        line = _ANSI_RE.sub("", raw).strip()
        match = _WHATWEB_PLAIN.match(line)
        if match is None:
            continue
        pairs = [_plugin_name_value(seg) for seg in _split_top_level(match.group("plugins"))]
        path = _path_of(match.group("url"))
        status = int(match.group("status"))
        rendered = _render_plugins(pairs)
        findings.append(
            HttpFinding(
                port=port,
                path=path,
                status=status,
                note=f"whatweb: {rendered}" if rendered else "whatweb",
            )
        )
        findings += _redirect_findings(pairs, port, path, status)
    return findings


def parse_whatweb(text: str, port: int) -> list[HttpFinding]:
    # whatweb emits JSON (--log-json) or the default human summary line. Parse JSON first (richer);
    # fall back to the plain summary so the default `whatweb --colour=never <url>` still yields a
    # finding instead of silently dropping the fingerprint (e.g. an exposed login form).
    findings = _parse_whatweb_json(text, port)
    return findings if findings else _parse_whatweb_plain(text, port)


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
