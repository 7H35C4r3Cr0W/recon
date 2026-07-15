from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path

from oscprecon.models import Command, Finding, Port, Proto, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.http.parsers import (
    HttpFinding,
    detect_wordpress,
    is_vhost_host,
    parse_tool,
)

__all__ = [
    "EXTENSION_PRESETS",
    "HTTP_SERVICE_NAMES",
    "STATUS_PRESETS",
    "WIDE_NET_GROUPS",
    "HttpFinding",
    "HttpModule",
    "HttpScanSettings",
    "build_command",
    "default_output",
    "default_url",
    "detect_wordpress",
    "is_tls",
    "is_vhost_host",
    "parse_tool",
    "wide_net_extensions",
]

HTTP_SERVICE_NAMES = frozenset(
    {"http", "https", "http-alt", "http-proxy", "ssl/http", "ssl/https", "ssl/https-alt"}
)

# CLAUDE.md §9 extension preset groups (user-expanded).
EXTENSION_PRESETS: dict[str, list[str]] = {
    "Web stack": [
        "php",
        "phps",
        "php3",
        "php4",
        "php5",
        "php7",
        "phtml",
        "asp",
        "aspx",
        "ashx",
        "asmx",
        "jsp",
        "jspx",
        "do",
        "action",
        "cfm",
        "cfml",
    ],
    "Static": ["html", "htm", "xhtml", "shtml", "txt", "md"],
    "Scripts": ["js", "ts", "jsx", "tsx", "mjs", "cjs"],
    "Styles": ["css", "scss", "less"],
    "Backups": ["bak", "backup", "old", "swp", "swo", "orig", "tmp", "save", "sav", "dump", "~"],
    "Archives": ["zip", "tar", "tar.gz", "tgz", "tbz2", "7z", "rar", "gz", "bz2"],
    "Config": ["conf", "config", "ini", "inc", "env", "properties", "cfg", "yaml", "yml", "toml"],
    "Data/logs": ["log", "sql", "sqlite", "sqlite3", "db", "xml", "json", "csv"],
    "Server": ["htaccess", "htpasswd", "wsgi", "cgi", "pl", "py", "rb", "sh"],
    "Docs": ["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx"],
    "Microsoft": ["asp", "aspx", "cfm", "config"],
}

# "Wide net" default = union of these groups (order preserved, de-duplicated).
WIDE_NET_GROUPS = ["Web stack", "Static", "Backups", "Archives", "Config", "Data/logs"]

STATUS_PRESETS: dict[str, list[int]] = {
    "Found-only": [200, 204, 301, 302, 307],
    "+ Auth-protected": [200, 204, 301, 302, 307, 401, 403],
    "All informative": [200, 204, 301, 302, 307, 401, 403, 404, 500],
}

_TLS_SERVICES = {"https", "ssl/http", "ssl/https", "ssl/https-alt"}
_TLS_PORTS = {443, 4443, 8443, 9443}


def wide_net_extensions() -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for group in WIDE_NET_GROUPS:
        for ext in EXTENSION_PRESETS[group]:
            if ext not in seen:
                seen.add(ext)
                result.append(ext)
    return result


def is_tls(service_name: str, port: int) -> bool:
    return service_name.lower() in _TLS_SERVICES or port in _TLS_PORTS


def _bracket_host(host: str) -> str:
    try:
        if ipaddress.ip_address(host).version == 6:
            return f"[{host}]"  # RFC 3986 requires brackets around an IPv6 literal in a URL
    except ValueError:
        pass
    return host


def default_url(host: str, port: int, tls: bool) -> str:
    scheme = "https" if tls else "http"
    default_port = 443 if tls else 80
    host = _bracket_host(host)
    if port == default_port:
        return f"{scheme}://{host}/"
    return f"{scheme}://{host}:{port}/"


def default_output(port: int, tool: str, wordlist: str) -> str:
    stem = Path(wordlist).stem or "wordlist"
    return f"http/{port}/{tool}-{stem}.txt"


@dataclass
class HttpScanSettings:
    tool: str
    url: str
    wordlist: str
    extensions: list[str] = field(default_factory=list)
    threads: int = 40
    depth: int = 2
    timeout: int = 10
    rate_limit: int | None = None
    skip_tls: bool = True
    status_codes: list[int] = field(default_factory=list)
    output_file: str = ""


def _csv(values: list[int]) -> str:
    return ",".join(str(v) for v in values)


def _build_feroxbuster(s: HttpScanSettings) -> str:
    parts = ["feroxbuster", "-u", s.url, "-w", s.wordlist]
    if s.extensions:
        parts += ["-x", ",".join(s.extensions)]
    parts += ["-d", str(s.depth), "-t", str(s.threads), "--timeout", str(s.timeout)]
    if s.rate_limit:
        parts += ["--rate-limit", str(s.rate_limit)]
    if s.skip_tls:
        parts += ["-k"]
    if s.status_codes:
        parts += ["-s", _csv(s.status_codes)]
    if s.output_file:
        parts += ["-o", s.output_file]
    return " ".join(parts)


def _build_gobuster(s: HttpScanSettings) -> str:
    parts = ["gobuster", "dir", "-u", s.url, "-w", s.wordlist]
    if s.extensions:
        parts += ["-x", ",".join(s.extensions)]
    parts += ["-t", str(s.threads), "--timeout", f"{s.timeout}s"]
    if s.skip_tls:
        parts += ["-k"]
    if s.status_codes:
        parts += ["-b", '""', "-s", _csv(s.status_codes)]
    if s.output_file:
        parts += ["-o", s.output_file]
    return " ".join(parts)


def _build_ffuf(s: HttpScanSettings) -> str:
    url = s.url if "FUZZ" in s.url else s.url.rstrip("/") + "/FUZZ"
    parts = ["ffuf", "-u", url, "-w", s.wordlist]
    if s.extensions:
        parts += ["-e", "." + ",.".join(s.extensions)]
    parts += ["-t", str(s.threads), "-timeout", str(s.timeout)]
    if s.depth:
        parts += ["-recursion", "-recursion-depth", str(s.depth)]
    if s.rate_limit:
        parts += ["-rate", str(s.rate_limit)]
    if s.status_codes:
        parts += ["-mc", _csv(s.status_codes)]
    if s.output_file:
        parts += ["-o", s.output_file, "-of", "json"]
    return " ".join(parts)


def _build_dirsearch(s: HttpScanSettings) -> str:
    parts = ["dirsearch", "-u", s.url, "-w", s.wordlist]
    if s.extensions:
        parts += ["-e", ",".join(s.extensions)]
    parts += ["-t", str(s.threads), "--timeout", str(s.timeout)]
    if s.depth:
        parts += ["-r", "--recursion-depth", str(s.depth)]
    if s.status_codes:
        parts += ["-i", _csv(s.status_codes)]
    if s.output_file:
        parts += ["-o", s.output_file]
    return " ".join(parts)


def build_command(settings: HttpScanSettings) -> str:
    if settings.tool == "gobuster":
        return _build_gobuster(settings)
    if settings.tool == "ffuf":
        return _build_ffuf(settings)
    if settings.tool == "dirsearch":
        return _build_dirsearch(settings)
    return _build_feroxbuster(settings)


class HttpModule(Module):
    name = "http"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(s.service.lower() in HTTP_SERVICE_NAMES for s in scan_results.services)

    def http_ports(self, scan_results: ScanResults) -> list[tuple[int, bool]]:
        return [
            (s.port, is_tls(s.service, s.port))
            for s in scan_results.services
            if s.service.lower() in HTTP_SERVICE_NAMES
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        commands: list[Command] = []
        for port in ports:
            tls = is_tls(port.service, port.number)
            # target.host prefers the vhost name when set, so probes hit name-based virtual hosts
            # (e.g. thetoppers.htb) that the bare IP won't serve — requires the /etc/hosts entry.
            url = default_url(target.host, port.number, tls)
            base = f"http/{port.number}"
            commands += [
                Command(
                    "http",
                    # --colour=never: whatweb colours its summary even when piped, so without this
                    # the saved file is full of ANSI escapes and the parser can't read the plugins.
                    f"whatweb --colour=never {url}",
                    "Fingerprint the web stack.",
                    "< 30s",
                    f"{base}/whatweb.txt",
                ),
                Command(
                    "http", f"curl -sIk {url}", "Response headers.", "< 30s", f"{base}/headers.txt"
                ),
                Command(
                    "http",
                    f"curl -sk {url}robots.txt",
                    "robots.txt disclosure.",
                    "< 30s",
                    f"{base}/robots.txt",
                ),
                Command(
                    "http",
                    f"curl -sk {url}sitemap.xml",
                    "sitemap.xml disclosure.",
                    "< 30s",
                    f"{base}/sitemap.xml",
                ),
                Command(
                    "http",
                    f"curl -sk {url}.git/HEAD",
                    "Exposed .git check.",
                    "< 30s",
                    f"{base}/git-head.txt",
                ),
            ]
        return commands

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for label, text in raw_outputs.items():
            tool, _, port_str = label.partition(":")
            port = int(port_str) if port_str.isdigit() else 0
            for hf in parse_tool(tool, text, port):
                findings.append(
                    Finding(
                        service="http",
                        title=f"{hf.status} {hf.path}".strip(),
                        detail=hf.note,
                        port=hf.port or None,
                        proto=Proto.TCP,
                        fields={
                            "path": hf.path,
                            "status": str(hf.status),
                            "size": str(hf.size),
                            "redirect_to": hf.redirect_to,
                        },
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        out: list[str] = []
        blob = " ".join(f.detail for f in findings)
        if detect_wordpress(blob):
            out.append(
                "WordPress detected — enumerate (never brute): "
                "wpscan --enumerate vp,vt,tt,cb,dbe,u,m --url {url}"
            )
        hosts = sorted(
            {
                str(f.fields.get("redirect_to", ""))
                for f in findings
                if is_vhost_host(str(f.fields.get("redirect_to", "")))
            }
        )
        for host in hosts:
            out.append(
                f"Name-based virtual host '{host}' found via redirect — add it to /etc/hosts and "
                f"enumerate it as a vhost (Host: FUZZ.{host}); it may serve content the IP won't."
            )
        return out
