from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.http import HTTP_SERVICE_NAMES
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
    return f"vhost/{tool}.json" if tool == "ffuf" else f"vhost/{tool}.txt"


def wildcard_probe_command(scheme: str, target: str, domain: str) -> str:
    # why: probe a definitely-nonexistent vhost; its response size is the wildcard baseline to -fs.
    label = "zzq-nonexistent-wildcard-probe"
    return (
        f'curl -sk -o /dev/null -w "%{{size_download}}" '
        f'-H "Host: {label}.{domain}" {scheme}://{target}/'
    )


def _build_ffuf(s: VhostScanSettings) -> str:
    parts = [
        "ffuf",
        "-u",
        f"{s.scheme}://{s.target}/",
        "-H",
        f'"Host: FUZZ.{s.domain}"',
        "-w",
        s.wordlist,
    ]
    if s.filter_size is not None:
        parts += ["-fs", str(s.filter_size)]
    parts += ["-t", str(s.threads)]
    if s.output_file:
        parts += ["-o", s.output_file, "-of", "json"]
    return " ".join(parts)


def _build_gobuster_vhost(s: VhostScanSettings) -> str:
    parts = [
        "gobuster",
        "vhost",
        "-u",
        f"{s.scheme}://{s.domain}/",
        "-w",
        s.wordlist,
        "--append-domain",
        "-t",
        str(s.threads),
    ]
    if s.output_file:
        parts += ["-o", s.output_file]
    return " ".join(parts)


def _build_gobuster_dns(s: VhostScanSettings) -> str:
    parts = ["gobuster", "dns", "-d", s.domain, "-w", s.wordlist, "-t", str(s.threads)]
    if s.dns_server:
        parts += ["-r", s.dns_server]
    if s.output_file:
        parts += ["-o", s.output_file]
    return " ".join(parts)


def _build_dnsrecon(s: VhostScanSettings) -> str:
    parts = ["dnsrecon", "-d", s.domain, "-t", "brt", "-D", s.wordlist]
    if s.dns_server:
        parts += ["-n", s.dns_server]
    return " ".join(parts)


def _build_wfuzz(s: VhostScanSettings) -> str:
    parts = ["wfuzz", "-c", "-w", s.wordlist, "-H", f'"Host: FUZZ.{s.domain}"']
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
        if vhosts:
            return [f"Enumerate discovered vhost as a new HTTP target: {vhosts[0]}"]
        return []
