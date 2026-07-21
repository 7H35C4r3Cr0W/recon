from __future__ import annotations

import ipaddress
import shlex
from dataclasses import dataclass, field
from pathlib import Path

from oscprecon.models import Command, Finding, Port, Proto, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.http.parsers import (
    HttpFinding,
    detect_api_server,
    detect_ua_gate,
    detect_wordpress,
    email_domains_from_plugins,
    is_vhost_host,
    lab_hostnames_from_text,
    parse_tool,
    vhost_from_redirect,
)

# why: paths (wordlist/output) and the URL can carry a space (a ~/wordlists/ dir, a typed output
# name) that shell.run's shlex.split would break into two argv tokens. Quote them so the assembled
# command survives the round-trip. shlex.quote adds quotes ONLY when needed, so ordinary paths are
# emitted verbatim and existing command strings are unchanged. [#35]
_q = shlex.quote

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
    "detect_api_server",
    "detect_ua_gate",
    "detect_wordpress",
    "effective_web_host",
    "host_resolves",
    "email_domains_from_plugins",
    "is_tls",
    "is_vhost_host",
    "lab_hostnames_from_text",
    "parse_tool",
    "vhost_from_redirect",
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


def host_resolves(name: str) -> bool:
    # True if the name resolves via DNS or /etc/hosts. Used to avoid pointing http probes at a vhost
    # the operator hasn't added to /etc/hosts yet (which fails with "no address" and zeroes recon).
    import socket

    try:
        socket.getaddrinfo(name, None)
    except OSError:
        return False
    return True


def effective_web_host(target: Target) -> tuple[str, bool]:
    # Returns (host_to_probe, hostname_unresolved). A hostname is correct for name-based vhosts, but
    # only if it resolves — when it doesn't, every whatweb/curl/ferox probe fails and http recon
    # silently returns nothing (seen live on HTB Holiday + Falafel). Fall back to the IP so recon
    # works, and flag it so the caller can tell the operator to add the /etc/hosts entry.
    name = target.hostname
    if name and name != target.ip and not host_resolves(name):
        return target.ip, True
    return target.host, False


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
    # empty = the tool's own default UA (matches the §9 reference command). Set a full browser UA to
    # defeat apps that filter by User-Agent — some (Node/Express, WAFs) 404/403 a curl/ferox/
    # gobuster UA and only serve real content to a browser string. See suggest()'s UA-gate hint.
    user_agent: str = ""


def _csv(values: list[int]) -> str:
    return ",".join(str(v) for v in values)


def _build_feroxbuster(s: HttpScanSettings) -> str:
    parts = ["feroxbuster", "-u", _q(s.url), "-w", _q(s.wordlist)]
    if s.extensions:
        parts += ["-x", ",".join(s.extensions)]
    parts += ["-d", str(s.depth), "-t", str(s.threads), "--timeout", str(s.timeout)]
    if s.rate_limit:
        parts += ["--rate-limit", str(s.rate_limit)]
    if s.skip_tls:
        parts += ["-k"]
    if s.user_agent:
        parts += ["-a", _q(s.user_agent)]
    if s.status_codes:
        parts += ["-s", _csv(s.status_codes)]
    if s.output_file:
        parts += ["-o", _q(s.output_file)]
    return " ".join(parts)


def _build_gobuster(s: HttpScanSettings) -> str:
    parts = ["gobuster", "dir", "-u", _q(s.url), "-w", _q(s.wordlist)]
    if s.extensions:
        parts += ["-x", ",".join(s.extensions)]
    parts += ["-t", str(s.threads), "--timeout", f"{s.timeout}s"]
    if s.skip_tls:
        parts += ["-k"]
    if s.user_agent:
        parts += ["-a", _q(s.user_agent)]
    if s.status_codes:
        parts += ["-b", '""', "-s", _csv(s.status_codes)]
    if s.output_file:
        parts += ["-o", _q(s.output_file)]
    return " ".join(parts)


def _build_ffuf(s: HttpScanSettings) -> str:
    url = s.url if "FUZZ" in s.url else s.url.rstrip("/") + "/FUZZ"
    parts = ["ffuf", "-u", _q(url), "-w", _q(s.wordlist)]
    if s.extensions:
        parts += ["-e", "." + ",.".join(s.extensions)]
    parts += ["-t", str(s.threads), "-timeout", str(s.timeout)]
    if s.depth:
        parts += ["-recursion", "-recursion-depth", str(s.depth)]
    if s.rate_limit:
        parts += ["-rate", str(s.rate_limit)]
    if s.user_agent:
        parts += ["-H", _q(f"User-Agent: {s.user_agent}")]
    if s.status_codes:
        parts += ["-mc", _csv(s.status_codes)]
    if s.output_file:
        parts += ["-o", _q(s.output_file), "-of", "json"]
    return " ".join(parts)


def _build_dirsearch(s: HttpScanSettings) -> str:
    parts = ["dirsearch", "-u", _q(s.url), "-w", _q(s.wordlist)]
    if s.extensions:
        parts += ["-e", ",".join(s.extensions)]
    parts += ["-t", str(s.threads), "--timeout", str(s.timeout)]
    if s.depth:
        parts += ["-r", "--recursion-depth", str(s.depth)]
    if s.user_agent:
        parts += ["--user-agent", _q(s.user_agent)]
    if s.status_codes:
        parts += ["-i", _csv(s.status_codes)]
    if s.output_file:
        parts += ["-o", _q(s.output_file)]
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
        # target.host prefers the vhost name when set (so probes hit name-based virtual hosts like
        # thetoppers.htb) — but only if it resolves; an unresolved hostname makes every probe fail,
        # so effective_web_host falls back to the IP (add the /etc/hosts entry to enable the vhost).
        web_host, _ = effective_web_host(target)
        for port in ports:
            tls = is_tls(port.service, port.number)
            url = default_url(web_host, port.number, tls)
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
                            "base_path": hf.base_path,
                            "email_domain": hf.email_domain,
                            "page_host": hf.page_host,
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
        # an ASGI/JSON API (uvicorn/FastAPI) is enumerated by its schema, not by dir-busting for
        # files — the auto-generated docs list every route and its expected parameters (§14 lookup).
        if detect_api_server(blob):
            out.append(
                "JSON API server detected (uvicorn/FastAPI/Starlette) — enumerate the API "
                "surface, not just files: curl the auto-generated docs/schema (/openapi.json, "
                "/docs, /redoc, /swagger.json) and probe versioned roots (/api, /api/v1). They "
                "list every route and its parameters."
            )
        # the root returned a 404/Error page — often a missing / route, but also the classic tell of
        # a User-Agent filter: some apps 404/403 a curl/ferox/gobuster (or no) UA and serve real
        # content ONLY to a full browser string. Cheap to rule out, and it's why the tool's default
        # probes can see an empty site the browser doesn't (§9).
        if detect_ua_gate(blob):
            out.append(
                "Root returned a 404/Error page — if the site looks empty it may be a missing "
                "route OR a User-Agent filter (some apps 404 a curl/feroxbuster/no-UA request and "
                "only serve a full browser string). Re-probe with a browser UA: curl -A 'Mozilla/"
                "5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' {url} — if content appears, "
                "set that User-Agent for content discovery (feroxbuster -a / ffuf -H)."
            )
        # a Location is a bare host (whatweb), a full URL (ferox/gobuster/ffuf) or a relative path;
        # vhost_from_redirect pulls the hostname from any of them, so 'http://internal.htb/' shows.
        hosts = sorted(
            {
                host
                for f in findings
                if (host := vhost_from_redirect(str(f.fields.get("redirect_to", ""))))
            }
        )
        for host in hosts:
            out.append(
                f"Name-based virtual host '{host}' found via redirect — add it to /etc/hosts and "
                f"enumerate it as a vhost (Host: FUZZ.{host}); it may serve content the IP won't."
            )
        # a root redirect into a subdirectory means the whole app is served from that base path.
        bases = sorted({b for f in findings if (b := str(f.fields.get("base_path", "")).strip())})
        for base in bases:
            stripped = base.lstrip("/")
            out.append(
                f"Site root redirects to '{base}' — the app is served from this base path. Point "
                f"content discovery, whatweb and nikto at it (feroxbuster -u {{url}}{stripped}), "
                f"not /; enumerating / will miss everything."
            )
        # an email disclosed on the page ("info@snoopy.htb") usually names the box's real domain —
        # the prerequisite for vhost/subdomain enumeration that the bare IP never serves (§10). This
        # is a weaker signal than an nmap/whatweb redirect (contact info, not the server naming
        # itself), so surface it as a loud lead rather than auto-setting the hostname.
        email_domains = sorted(
            {d for f in findings if (d := str(f.fields.get("email_domain", "")).strip())}
        )
        for domain in email_domains:
            out.append(
                f"Email domain '{domain}' disclosed on the page — likely the target domain. Add it "
                f"to /etc/hosts, Set Target Hostname, and enumerate vhosts/subdomains "
                f"(ffuf -H 'Host: FUZZ.{domain}' …); a name-based vhost may serve content the IP "
                f"won't."
            )
        # a lab hostname printed in the page body (heading/footer/comment, e.g. carpediem.htb) is
        # almost always the box's domain — the vhost-enum prerequisite the bare IP never serves. A
        # loud lead like the email domain (weaker than a redirect, so surface it, don't auto-set).
        page_hosts = sorted(
            {h for f in findings if (h := str(f.fields.get("page_host", "")).strip())}
        )
        for host in page_hosts:
            out.append(
                f"Host '{host}' disclosed in the page content — likely the target domain/vhost. "
                f"Add it to /etc/hosts, Set Target Hostname, and enumerate vhosts/subdomains "
                f"(ffuf -H 'Host: FUZZ.{host}' …); a name-based vhost may serve content the IP "
                f"won't."
            )
        # a 401 endpoint wants HTTP auth — a SINGLE attempt with a well-known default is Tier-2
        # recon-adjacent (§2), never a wordlist. Surface it so the operator one-shots a default.
        auth_paths = sorted(
            {
                str(f.fields.get("path", ""))
                for f in findings
                if str(f.fields.get("status")) == "401"
            }
        )
        for p in auth_paths[:3]:
            stripped = p.lstrip("/")
            out.append(
                f"{p} returned 401 Unauthorized — if it's HTTP Basic auth, try ONE well-known "
                f"default by hand (curl -u admin:admin {{url}}{stripped}); a single attempt is "
                f"recon-adjacent, not a password spray."
            )
        return out
