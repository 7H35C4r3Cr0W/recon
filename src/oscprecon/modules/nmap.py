from __future__ import annotations

import re
from datetime import UTC, datetime

from oscprecon.models import (
    Command,
    DiscoveredService,
    Finding,
    Port,
    Proto,
    ScanResults,
    Target,
)
from oscprecon.modules.base import Module

_PORT_LINE = re.compile(
    r"^(?P<port>\d+)/(?P<proto>tcp|udp)\s+"
    r"(?P<state>open(?:\|filtered)?)\s+"
    r"(?P<service>\S+)(?:\s+(?P<rest>.*\S))?\s*$"
)

# a port nmap explicitly lists as "filtered" (a firewall dropped the probe) — NOT a confirmed
# service, but worth surfacing: on boxes like Drive, 3000/tcp is filtered from outside yet runs
# Gitea, reachable only after a foothold + SSH forward. Kept out of discovered_services (so it
# never becomes an actionable/present node) and surfaced as an informational finding instead.
_FILTERED_PORT_LINE = re.compile(r"^(?P<port>\d+)/(?P<proto>tcp|udp)\s+filtered\s+(?P<service>\S+)")

# nmap's http-title NSE prints "Did not follow redirect to http://ignition.htb/" when a name-based
# vhost box bounces the IP to its hostname — that hostname is the whole recon on such boxes.
_REDIRECT_TITLE_RE = re.compile(
    r"follow(?:ed)?\s+redirect\s+to\s+https?://([A-Za-z0-9.-]+)", re.IGNORECASE
)
# a real vhost name: a letter + a dotted TLD, so a bare IP redirect is not mistaken for a vhost.
_VHOST_HOST_RE = re.compile(r"^(?=.*[A-Za-z])[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
# a version-shaped token: a dotted/dashed number (2.4.52, 8.2p1, 0.8.13). A product name that starts
# with a digit (3proxy, 3CX, 7-Zip) does NOT match, so it is not mistaken for its own version.
_VERSION_RE = re.compile(r"^v?\d+([.\-]\d+)+")

# `nmap --reason` (offered in the custom Scan dialog) inserts a REASON column between SERVICE and
# VERSION — "22/tcp open ssh syn-ack ttl 64 OpenSSH 8.2p1". Without stripping it, the reason text
# ("syn-ack ttl 64") is folded into `product`, polluting discovered_services and the searchsploit
# / EDB lookup. The reason is one token from nmap's fixed vocabulary, optionally followed by
# "ttl <n>"; strip it only when the leading token is a KNOWN reason, so a real lowercase product
# (nginx, lighttpd) is never mistaken for a reason and eaten.
_NMAP_REASONS = frozenset(
    {
        "syn-ack", "syn", "split-handshake-syn", "reset", "no-response", "init-timeout",
        "conn-refused", "conn-timeout", "perc-timeout", "udp-response", "tcp-response",
        "proto-response", "arp-response", "nd-response", "ip-response", "localhost-response",
        "unknown-response", "host-unreach", "net-unreach", "proto-unreach", "port-unreach",
        "dest-unreach", "echo-reply", "time-exceeded", "ttl-exceeded", "admin-prohibited",
        "host-prohibited", "net-prohibited", "source-quench", "redirect", "user-set", "script-set",
    }
)  # fmt: skip
# why: anchor the tail on (?=\s|$), NOT a mandatory \s+ — otherwise when "<reason> ttl <n>" is the
# WHOLE remainder (no -sV banner follows, the common case for a bare `--reason` scan), the trailing
# \s+ can't match after the digits, the engine backtracks and drops the ttl group, and only
# "<reason> " is stripped — leaving "ttl 64" to be mis-parsed as product='ttl' version='64' (#1).
_REASON_PREFIX = re.compile(r"^(?P<reason>[a-z][a-z-]*)(?:\s+ttl\s+\d+)?(?=\s|$)")


def _strip_reason(rest: str) -> str:
    # drop a leading "<reason> [ttl <n>] " column that `--reason` prepends to the version banner.
    match = _REASON_PREFIX.match(rest)
    if match is not None and match.group("reason") in _NMAP_REASONS:
        return rest[match.end() :].lstrip()
    return rest


def redirect_vhosts(raw_outputs: dict[str, str]) -> list[str]:
    """Vhost hostnames nmap saw the target redirect to (http-title 'Did not follow redirect …')."""
    hosts: list[str] = []
    for text in raw_outputs.values():
        for match in _REDIRECT_TITLE_RE.finditer(text):
            host = match.group(1).rstrip("/").lower()
            if _VHOST_HOST_RE.match(host) and host not in hosts:
                hosts.append(host)
    return hosts


# nmap's ssl-cert NSE (run by -sC on a TLS port) prints the certificate's Subject CN and Subject
# Alternative Names — a self-signed lab cert almost always carries the box's real hostname/vhost
# there (EarlyAccess: CN=earlyaccess.htb), the host-based-recon prerequisite the bare IP never
# serves. Mine the Subject CN (NOT the Issuer, a CA on a real cert) and every SAN DNS name.
_CERT_CN_RE = re.compile(r"commonname=(?P<host>[a-z0-9*.\-]+)", re.IGNORECASE)
_CERT_SAN_RE = re.compile(r"dns:(?P<host>[a-z0-9*.\-]+)", re.IGNORECASE)
# boilerplate CNs of a default/appliance self-signed cert — never a box vhost, never auto-set.
_GENERIC_CERT_HOSTS = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "example.com",
        "example.org",
        "example.net",
        "domain.com",
        "changeme",
    }
)


def cert_hostnames(raw_outputs: dict[str, str]) -> list[str]:
    """Box hostnames from nmap's ssl-cert NSE — Subject CN first, then SAN DNS names; lower-cased,
    deduped, and filtered (drops IPs, bare names, wildcards' `*.`, and boilerplate default CNs)."""
    cns: list[str] = []
    sans: list[str] = []
    for text in raw_outputs.values():
        for raw_line in text.splitlines():
            low = raw_line.lower()
            # the Subject CN line; skip Issuer (a CA on a real cert, same host on self-signed)
            if "commonname=" in low and "subject:" in low and "issuer" not in low:
                match = _CERT_CN_RE.search(raw_line)
                if match is not None:
                    cns.append(match.group("host"))
            for match in _CERT_SAN_RE.finditer(raw_line):  # SAN DNS: entries (the cert's own names)
                sans.append(match.group("host"))
    hosts: list[str] = []
    seen: set[str] = set()
    for raw_host in cns + sans:  # CN first so it is the canonical (auto-set) candidate
        host = raw_host.strip().lower().lstrip("*").lstrip(".").strip(".")
        if not host or host in seen:
            continue
        seen.add(host)
        if host in _GENERIC_CERT_HOSTS or not _VHOST_HOST_RE.match(host):
            continue
        hosts.append(host)
    return hosts


# nmap's http-robots.txt NSE (run by -sC) reports the paths a site's robots.txt disallows — admins
# hide admin panels, backups and the-thing-they-don't-want-indexed there, so each is a high-value
# recon lead surfaced for FREE by the scan (Spooktrol: /file_management/?file=implant). The header
# is "| http-robots.txt: N disallowed entr…" and the paths follow on "|_/path" continuation lines.
# The count/whitespace between the header and "disallowed" is one char class (never `\s*\d*\s*`,
# whose overlapping quantifiers backtrack O(n²) on a long whitespace run in target-served output).
_ROBOTS_NSE_HEADER = re.compile(r"http-robots\.txt:[\s\d]*disallowed", re.IGNORECASE)


def _strip_gutter(line: str) -> str:
    # drop nmap's NSE gutter ("| ", "|_", "|   ") so the script text/path is matched cleanly.
    stripped = line.strip()
    if stripped.startswith("|"):
        stripped = stripped[1:]
    if stripped.startswith("_"):
        stripped = stripped[1:]
    return stripped.strip()


def robots_disclosures(raw_outputs: dict[str, str]) -> list[str]:
    """Disallowed paths nmap's http-robots.txt NSE reported, deduped in first-seen order."""
    paths: list[str] = []
    seen: set[str] = set()
    for text in raw_outputs.values():
        collecting = False
        for raw_line in text.splitlines():
            line = _strip_gutter(raw_line)
            if _ROBOTS_NSE_HEADER.search(line):
                collecting = True
                continue
            if not collecting:
                continue
            # a genuine robots continuation line is ONLY whitespace-separated '/'-paths; the moment
            # a line isn't (e.g. the next NSE script "http-title: Index of /files"), the block ends
            # — else that title's '/files' token would be mis-captured as a disallowed path.
            tokens = line.split()
            if not tokens or not all(t.startswith("/") for t in tokens):
                collecting = False
                continue
            for token in tokens:
                if token not in seen:
                    seen.add(token)
                    paths.append(token)
    return paths


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


class NmapModule(Module):
    name = "nmap"

    def __init__(self, udp_full: bool = False, scan_profile: str = "default") -> None:
        self.udp_full = udp_full
        # why: unknown profiles fall back to the standard battery rather than raising — a stale
        # or hand-edited pref must never wedge the scan. config.Settings.normalized() validates
        # the persisted value; this is defence-in-depth for direct callers.
        self.scan_profile = scan_profile if scan_profile in ("quick", "full", "exam") else "default"

    def triggers(self, scan_results: ScanResults) -> bool:
        return True

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        host = target.ip
        if not ports:
            return self._discovery_battery(host)

        tcp_ports = sorted({p.number for p in ports if p.proto == Proto.TCP})
        if not tcp_ports:
            return []
        joined = ",".join(str(p) for p in tcp_ports)
        return [
            Command(
                "nmap",
                f"nmap -sV -sC -p {joined} {host}",
                "Version + default-script scan on the discovered open TCP ports.",
                "1-5 min",
                "nmap/tcp-versioned.txt",
            )
        ]

    def _discovery_battery(self, host: str) -> list[Command]:
        # why: the profile only shapes the DISCOVERY phase; the versioned -sV -sC scan on found
        # ports is identical everywhere. exam-legal by construction — every line is `nmap` with
        # allow-listed flags, never `--script vuln` (opt-in via Nmap presets, not the auto battery).
        top1000 = Command(
            "nmap",
            f"nmap --top-ports 1000 {host}",
            "Fast sweep of the 1000 most common TCP ports.",
            "< 1 min",
            "nmap/tcp-top1000.txt",
        )
        top1000_fast = Command(
            "nmap",
            f"nmap --top-ports 1000 -T4 {host}",
            "Fast sweep of the 1000 most common TCP ports (speed-tuned).",
            "< 1 min",
            "nmap/tcp-top1000.txt",
        )
        udp_top100 = Command(
            "nmap",
            f"nmap -sU --top-ports 100 {host}",
            "UDP top-100 — SNMP/DNS/NetBIOS/TFTP hide here.",
            "1-5 min",
            "nmap/udp-top100.txt",
        )
        if self.scan_profile == "quick":
            return [top1000_fast]  # fast triage: no full -p-, no UDP
        if self.scan_profile == "exam":
            cmds = [
                top1000_fast,
                Command(
                    "nmap",
                    f"nmap -p- --min-rate 1000 -T4 {host}",
                    "Full 65535-port TCP sweep, rate-boosted to finish fast under exam time. "
                    "No --script vuln.",
                    "2-8 min",
                    "nmap/tcp-full.txt",
                ),
                udp_top100,
            ]
        else:  # default / full
            cmds = [
                top1000,
                Command(
                    "nmap",
                    # -T4 keeps the full sweep from crawling on a remote target (a plain `-p-` over
                    # a VPN can run 20-40 min) while staying reliable on a lab link — the money port
                    # is sometimes ONLY here (e.g. MSSQL 1433 outside the top-1000). Exam-legal:
                    # timing only, no --script. `exam` adds --min-rate 1000 for maximum speed.
                    f"nmap -p- -T4 {host}",
                    "Full 65535-port TCP sweep — catches services on odd ports (speed-tuned).",
                    "3-10 min",
                    "nmap/tcp-full.txt",
                ),
                udp_top100,
            ]
        return cmds

    def _udp_full_command(self, host: str) -> Command:
        return Command(
            "nmap",
            f"nmap -sU -p- {host}",
            "Full 65535-port UDP sweep — very slow; deferred to run after the versioned scan.",
            "slow",
            "nmap/udp-full.txt",
        )

    def deferred_commands(self, target: Target) -> list[Command]:
        # why: UDP -p- is hours-slow and low-yield, so it must never block the high-value versioned
        # TCP scan. The orchestrator runs these LAST (after -sV -sC) so the useful results land
        # first and the sweep can be cancelled once you have them. `full` includes it (what makes
        # `full` more than `default`); others only on the --udp-full opt-in (CLAUDE.md §8). `quick`
        # is TCP-only triage and never runs UDP, even with --udp-full.
        if self.scan_profile == "quick":
            return []
        if self.udp_full or self.scan_profile == "full":
            return [self._udp_full_command(target.ip)]
        return []

    def discovered_services(self, raw_outputs: dict[str, str]) -> list[DiscoveredService]:
        merged: dict[tuple[int, Proto], DiscoveredService] = {}
        for text in raw_outputs.values():
            for service in self._parse_text(text):
                key = (service.port, service.proto)
                existing = merged.get(key)
                if existing is None:
                    merged[key] = service
                    continue
                if service.product and not existing.product:
                    existing.product = service.product
                if service.version and not existing.version:
                    existing.version = service.version
                # the -sV scan (it carries product/version) has the AUTHORITATIVE service name — let
                # it override the bare port-table guess (e.g. 8080 'http-proxy' -> 'http'); a scan
                # with no product only fills a blank/unknown name.
                if service.service and (service.product or existing.service in ("", "unknown")):
                    existing.service = service.service
                # the versioned/-sC scan carries the NSE script block (http-title, ssh-hostkey,
                # ssl-cert, smb-os-discovery…) the bare port-table sweep never has — fill it so the
                # report/tree surface those details (#7). Never let a blank re-scan wipe a filled.
                if service.nmap_scripts_output and not existing.nmap_scripts_output:
                    existing.nmap_scripts_output = service.nmap_scripts_output
        return sorted(merged.values(), key=lambda s: (s.proto.value, s.port))

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for service in self.discovered_services(raw_outputs):
            title = f"{service.port}/{service.proto.value} {service.service}".strip()
            detail = " ".join(part for part in (service.product, service.version) if part)
            findings.append(
                Finding(
                    service=service.service or "unknown",
                    title=title,
                    detail=detail,
                    port=service.port,
                    proto=service.proto,
                )
            )
        findings.extend(self._filtered_findings(raw_outputs))
        return findings

    def _filtered_findings(self, raw_outputs: dict[str, str]) -> list[Finding]:
        # surface ports nmap lists as "filtered" — a firewall dropped the probe, so it's not a
        # confirmed service, but a filtered port often hides an internal service reachable only
        # after a foothold + pivot (Drive: 3000/tcp filtered -> Gitea via SSH forward). Deduped.
        seen: set[tuple[int, str]] = set()
        out: list[Finding] = []
        for text in raw_outputs.values():
            for line in text.splitlines():
                m = _FILTERED_PORT_LINE.match(line.strip())
                if m is None:
                    continue
                port, proto, svc = int(m.group("port")), m.group("proto"), m.group("service")
                if (port, proto) in seen:
                    continue
                seen.add((port, proto))
                out.append(
                    Finding(
                        service="filtered",
                        title=f"{port}/{proto} filtered ({svc})",
                        detail="filtered by a firewall — not confirmed open, but a service may be "
                        "here; revisit after a foothold/pivot (e.g. SSH local-forward) before "
                        "ruling it out.",
                        port=port,
                        proto=Proto(proto),
                    )
                )
        return out

    def suggest(self, findings: list[Finding]) -> list[str]:
        return []

    def _parse_text(self, text: str) -> list[DiscoveredService]:
        # Block parser: each port row owns the indented NSE script lines that follow it
        # (`| ssh-hostkey:`, `|_http-title: …`), captured into nmap_scripts_output so the report and
        # service tree can show the real enum detail — not just product/version (#7).
        services: list[DiscoveredService] = []
        current: DiscoveredService | None = None
        script_lines: list[str] = []

        def flush() -> None:
            if current is not None and script_lines:
                current.nmap_scripts_output = "\n".join(script_lines).rstrip()
            script_lines.clear()

        for raw in text.splitlines():
            service = parse_port_line(raw.strip())
            if service is not None:
                flush()
                services.append(service)
                current = service
                continue
            stripped = raw.strip()
            if current is not None and stripped.startswith("|"):
                script_lines.append(_clean_script_line(stripped))
            elif stripped and not stripped.startswith("|"):
                # a non-port, non-continuation line ("Service Info:", "Host script results:", "Nmap
                # done") ends the current port's NSE block — otherwise host-level scripts (smb-os-
                # discovery, clock-skew, smb-security-mode) get glued onto the last port row.
                flush()
                current = None
        flush()
        return services


def _clean_script_line(line: str) -> str:
    # strip nmap's NSE gutter marker ("| ", "|_", "|   ") but keep the nested indentation that
    # follows, so multi-line script output (hostkeys, cert SANs, smb-os-discovery) stays readable.
    body = line[1:]  # drop the leading '|'
    if body.startswith("_"):
        body = body[1:]
    if body.startswith(" "):
        body = body[1:]
    return body.rstrip()


def parse_port_line(line: str) -> DiscoveredService | None:
    """One nmap 'PORT STATE SERVICE VERSION' row → a DiscoveredService (None if not a port row).

    Reused by the pivot multi-host parser so both read nmap version columns identically."""
    match = _PORT_LINE.match(line.strip())
    if match is None:
        return None
    rest = _strip_reason(match.group("rest") or "")
    product = ""
    version = ""
    # a leading "(" means nmap detected no product name, just parenthetical extrainfo
    # (rsync's "(protocol version 31)"); leave product/version empty rather than mangle it.
    if rest and not rest.startswith("("):
        # nmap's version column is "<product> [version] [extrainfo]" with a free-text,
        # often multi-word product ("Redis key-value store", "Samba smbd", "Linux telnetd").
        # Split on the first version-looking token (starts with a digit) so product and
        # version are clean and extrainfo noise is dropped; with no version token the whole
        # banner is the product. Splitting on the first word instead mangled both fields
        # (product "Redis", version "key-value store 5.0.7").
        tokens = rest.split()
        # PREFER the first dotted/dashed version token (2.4.52, 14.00.1000.00, 8.2p1). An edition
        # YEAR like "2017" in "Microsoft SQL Server 2017 14.00.1000.00" is a BARE integer that must
        # not be mistaken for the version — so only when NO dotted token exists do we fall back to a
        # bare number past position 0 ("Foo 5" still splits; "3proxy"/"7-Zip" never self-split).
        vi = next((i for i, tok in enumerate(tokens) if _VERSION_RE.match(tok)), None)
        if vi is None:
            vi = next((i for i, tok in enumerate(tokens) if i > 0 and tok[:1].isdigit()), None)
        if vi is None:
            product = " ".join(tokens)
        else:
            product = " ".join(tokens[:vi])
            # strip banner punctuation glued to the version token (nmap's "14.00.1000.00; RTM+"
            # splits to "14.00.1000.00;") so the report/graph show a clean version
            version = tokens[vi].rstrip(";,")
    return DiscoveredService(
        port=int(match.group("port")),
        proto=Proto(match.group("proto")),
        service=match.group("service"),
        product=product,
        version=version,
        discovered_at=_now_iso(),
        state=match.group("state"),
    )
