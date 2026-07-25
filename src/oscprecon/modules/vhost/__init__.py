from __future__ import annotations

import shlex
from dataclasses import dataclass
from pathlib import Path

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.http import HTTP_SERVICE_NAMES
from oscprecon.modules.s3 import is_s3_host
from oscprecon.modules.vhost.parsers import VhostFinding, parse_vhost_tool

__all__ = [
    "DEFAULT_VHOST_WORDLIST",
    "TOOL_LABELS",
    "VhostFinding",
    "VhostModule",
    "VhostScanSettings",
    "build_command",
    "default_output",
    "parse_vhost_tool",
    "wildcard_probe_command",
]

DEFAULT_VHOST_WORDLIST = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"

# GUI label -> internal tool key. Active/target-directed only (passive OSINT needs internet, §2).
TOOL_LABELS = {
    "ffuf": "ffuf",
    "gobuster vhost": "gobuster-vhost",
    "gobuster dns": "gobuster-dns",
    "dnsrecon": "dnsrecon",
    "dnsenum": "dnsenum",
    "wfuzz": "wfuzz",
}


@dataclass
class VhostScanSettings:
    tool: str
    target: str
    domain: str
    wordlist: str
    scheme: str = "http"
    filter_size: int | None = None
    threads: int = 40
    dns_server: str = ""
    output_file: str = ""


def default_output(tool: str, wordlist: str) -> str:
    # the wordlist is part of the path: two vhost sweeps with different lists are different scans,
    # and now that they can run at the same time one must not overwrite (or be parsed as) the other.
    stem = Path(wordlist).stem if wordlist else ""
    suffix = f"-{stem}" if stem else ""
    return f"vhost/{tool}{suffix}.json" if tool == "ffuf" else f"vhost/{tool}{suffix}.txt"


def wildcard_probe_command(scheme: str, target: str, domain: str) -> str:
    # why: probe a definitely-nonexistent vhost; its response size is the wildcard baseline to -fs.
    label = "zzq-nonexistent-wildcard-probe"
    return (
        f'curl -sk -o /dev/null -w "%{{size_download}}" '
        f'-H "Host: {label}.{domain}" {scheme}://{target}/'
    )


# quote path fields so a space in a wordlist/output path survives shell.run's shlex.split (only adds
# quotes when needed, so ordinary paths are emitted verbatim). [#35]
_q = shlex.quote


def _build_ffuf(s: VhostScanSettings) -> str:
    parts = [
        "ffuf",
        "-u",
        f"{s.scheme}://{s.target}/",
        "-H",
        f'"Host: FUZZ.{s.domain}"',
        "-w",
        _q(s.wordlist),
    ]
    if s.filter_size is not None:
        parts += ["-fs", str(s.filter_size)]
    else:
        # auto-calibrate: filter the wildcard/default-vhost baseline. Without this (and with no -fs)
        # a box that serves the same page for any Host header matches ALL ~5000 payloads, flooding
        # findings with false vhosts (auto sweep passes filter_size=None). [#4]
        parts += ["-ac"]
    parts += ["-t", str(s.threads)]
    if s.output_file:
        # JSON to stdout, not output_file: shell.run redirects (stdout+stderr) into that file, so a
        # `-o <output_file>` collides and the JSON is interleaved with / overwritten by ffuf's
        # banner+progress — silently losing every vhost (HTB Fighter: 'members'). -s silences the
        # noise; the captured stream is just matched words + the JSON (parser tolerates the prefix).
        parts += ["-s", "-of", "json", "-o", "/dev/stdout"]
    return " ".join(parts)


def _build_gobuster_vhost(s: VhostScanSettings) -> str:
    # why: connect to the target IP and set the vhost via --domain + --append-domain, so it works
    # without the domain resolving (gobuster's own advice: use the IP as the URL).
    parts = [
        "gobuster",
        "vhost",
        "-u",
        f"{s.scheme}://{s.target}/",
        "-w",
        _q(s.wordlist),
        "--append-domain",
        "--domain",
        s.domain,
        "-t",
        str(s.threads),
    ]
    if s.output_file:
        parts += ["-o", _q(s.output_file)]
    return " ".join(parts)


def _build_gobuster_dns(s: VhostScanSettings) -> str:
    # why: gobuster >=3.7 uses --domain (not -d, which is --delay) and --resolver (no -r alias).
    parts = ["gobuster", "dns", "--domain", s.domain, "-w", _q(s.wordlist), "-t", str(s.threads)]
    if s.dns_server:
        parts += ["--resolver", s.dns_server]
    if s.output_file:
        parts += ["-o", _q(s.output_file)]
    return " ".join(parts)


def _build_dnsrecon(s: VhostScanSettings) -> str:
    parts = ["dnsrecon", "-d", s.domain, "-t", "brt", "-D", _q(s.wordlist)]
    if s.dns_server:
        parts += ["-n", s.dns_server]
    return " ".join(parts)


def _build_dnsenum(s: VhostScanSettings) -> str:
    # dnsenum: DNS-based subdomain brute (-f wordlist) plus NS/MX/host record enumeration and an
    # AXFR attempt against every nameserver it finds. Point it at the target's DNS server (or an
    # explicit one), skip the slow reverse-netblock scan (--noreverse, avoids external internet),
    # and disable colour so the streamed output parses. Streams to stdout — no -o (that writes XML).
    server = s.dns_server or s.target
    parts = ["dnsenum", "--nocolor", "--noreverse", "-f", _q(s.wordlist)]
    if server:
        parts += ["--dnsserver", server]
    parts += ["--threads", str(s.threads), s.domain]
    return " ".join(parts)


def _build_wfuzz(s: VhostScanSettings) -> str:
    parts = ["wfuzz", "-c", "-w", _q(s.wordlist), "-H", f'"Host: FUZZ.{s.domain}"']
    if s.filter_size is not None:
        parts += ["--hh", str(s.filter_size)]
    parts += ["-u", f"{s.scheme}://{s.target}/"]
    return " ".join(parts)


def build_command(settings: VhostScanSettings) -> str:
    if settings.tool == "gobuster-vhost":
        return _build_gobuster_vhost(settings)
    if settings.tool == "gobuster-dns":
        return _build_gobuster_dns(settings)
    if settings.tool == "dnsrecon":
        return _build_dnsrecon(settings)
    if settings.tool == "dnsenum":
        return _build_dnsenum(settings)
    if settings.tool == "wfuzz":
        return _build_wfuzz(settings)
    return _build_ffuf(settings)


class VhostModule(Module):
    name = "vhost"

    def triggers(self, scan_results: ScanResults) -> bool:
        has_http = any(s.service.lower() in HTTP_SERVICE_NAMES for s in scan_results.services)
        return has_http and bool(scan_results.target.hostname)

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        if not target.hostname:
            return []
        settings = VhostScanSettings(
            tool="ffuf",
            target=target.ip,
            domain=target.hostname,
            wordlist=DEFAULT_VHOST_WORDLIST,
            output_file="vhost/ffuf.json",
        )
        return [
            Command(
                "vhost",
                build_command(settings),
                "Virtual-host sweep (Host: FUZZ) with the small subdomain list.",
                "1-5 min",
                "vhost/ffuf.json",
            )
        ]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for label, text in raw_outputs.items():
            tool, _, domain = label.partition(":")
            for vf in parse_vhost_tool(tool, text, domain):
                findings.append(
                    Finding(
                        service="vhost",
                        title=vf.vhost,
                        detail=vf.note,
                        fields={
                            "vhost": vf.vhost,
                            "status": str(vf.status),
                            "size": str(vf.size),
                            "ip": vf.ip,
                        },
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        vhosts = [f.title for f in findings if f.service == "vhost"]
        out: list[str] = []
        if vhosts:
            out.append(f"Enumerate discovered vhost as a new HTTP target: {vhosts[0]}")
        # an s3.* vhost is an S3 endpoint (localstack/minio) — offer the read-only bucket listing.
        for host in vhosts:
            if is_s3_host(host):
                out.append(
                    f"'{host}' looks like an S3 endpoint — list buckets (read-only): "
                    f"aws --endpoint=http://{host} s3 ls"
                )
        return out
