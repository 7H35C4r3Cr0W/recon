from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target, validate_host
from oscprecon.modules.base import Module
from oscprecon.modules.dns.parsers import (
    DnsFinding,
    parse_dig_axfr,
    parse_dig_version,
    parse_dns_tool,
    parse_dnsrecon,
    parse_nmap_dns,
)

__all__ = [
    "DNS_SERVICE_NAMES",
    "DnsFinding",
    "DnsModule",
    "DnsStep",
    "normalize_domain",
    "parse_dig_axfr",
    "parse_dig_version",
    "parse_dns_tool",
    "parse_dnsrecon",
    "parse_nmap_dns",
]

DNS_SERVICE_NAMES = frozenset({"domain", "dns"})
_DNS_PORTS = frozenset({53})


@dataclass
class DnsStep:
    command: Command
    tool: str = ""  # parser key for the output, or "" when the output is not parsed


def normalize_domain(domain: str | None) -> str | None:
    # why: the domain is interpolated into dig/dnsrecon command lines, so it must pass the same
    # single-token host validation as Target.ip — anything with whitespace/leading-'-'/quotes is
    # rejected (returns None) so it can never smuggle a second argv token (§2).
    if not domain:
        return None
    candidate = domain.strip()
    try:
        return validate_host(candidate)
    except ValueError:
        return None


class DnsModule(Module):
    name = "dns"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in DNS_SERVICE_NAMES or s.port in _DNS_PORTS
            for s in scan_results.services
        )

    def recon_steps(
        self, target: Target, domain: str | None = None, port: int = 53
    ) -> list[DnsStep]:
        host = target.ip
        steps = [
            DnsStep(
                Command(
                    "dns",
                    f"dig @{host} version.bind CHAOS TXT +short",
                    "Grab the DNS server version string (recon).",
                    "< 30s",
                    "dns/dig-version.txt",
                ),
                "dig-version",
            ),
            DnsStep(
                Command(
                    "dns",
                    f"nmap -sV --script dns-nsid,dns-recursion -p {port} {host}",
                    "Server version (NSID) and recursion / open-resolver check (recon).",
                    "< 1 min",
                    "dns/nmap-dns.txt",
                ),
                "nmap-dns",
            ),
        ]
        resolved = normalize_domain(domain)
        if resolved is not None:
            steps.append(
                DnsStep(
                    Command(
                        "dns",
                        f"dig @{host} {resolved} AXFR",
                        "Attempt a zone transfer — dumps the whole zone if misconfigured (recon).",
                        "< 30s",
                        "dns/dig-axfr.txt",
                    ),
                    "dig-axfr",
                )
            )
            steps.append(
                DnsStep(
                    Command(
                        "dns",
                        f"dnsrecon -n {host} -d {resolved} -t std",
                        "Standard record enumeration (SOA/NS/MX/A/SRV) plus a zone-transfer try.",
                        "< 1 min",
                        "dns/dnsrecon-std.txt",
                    ),
                    "dnsrecon",
                )
            )
        return steps

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.recon_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for df in parse_dns_tool(tool, text):
                findings.append(
                    Finding(
                        service="dns",
                        title=f"{df.kind}: {df.value}",
                        detail=df.detail,
                        fields={"kind": df.kind, "value": df.value, "detail": df.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        out: list[str] = []
        if any(
            f.fields.get("kind") == "zone-transfer" and f.fields.get("value") == "allowed"
            for f in findings
        ):
            out.append(
                "Zone transfer succeeded — full DNS zone dumped; map the internal hostnames and "
                "IPs it reveals (recon)."
            )
        if any(
            f.fields.get("kind") == "recursion" and f.fields.get("value") == "enabled"
            for f in findings
        ):
            out.append(
                "DNS recursion enabled (open resolver) — note for the report; not exploited here."
            )
        versions = [
            f.fields.get("value", "") for f in findings if f.fields.get("kind") == "version"
        ]
        if versions:
            out.append(
                f"DNS server version '{versions[0]}' — look it up in the Exploit-DB pane (recon)."
            )
        return out
