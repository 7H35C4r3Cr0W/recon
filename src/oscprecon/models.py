from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from enum import StrEnum

# why: a host token is interpolated into command lines and split by shlex, so anything with
# whitespace or a leading '-' can smuggle extra flags (e.g. nmap --script *-brute). Accept only
# a valid IP or a strict DNS hostname — nothing that can become a separate argv token.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def validate_host(value: str) -> str:
    if not value or value.startswith("-") or any(ch.isspace() for ch in value):
        raise ValueError(f"invalid target host: {value!r}")
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    if _HOSTNAME_RE.match(value):
        return value
    raise ValueError(f"invalid target host: {value!r}")


class Proto(StrEnum):
    TCP = "tcp"
    UDP = "udp"


@dataclass(frozen=True)
class Target:
    ip: str
    hostname: str | None = None
    platform: str | None = None
    box_name: str | None = None
    os_guess: str | None = None

    def __post_init__(self) -> None:
        validate_host(self.ip)
        if self.hostname:
            validate_host(self.hostname)

    @property
    def host(self) -> str:
        # host-based recon (HTTP, vhost, S3) prefers the vhost name when set — many boxes serve the
        # real content only by Host header (name-based virtual hosting). IP-only tools use .ip.
        return self.hostname or self.ip


@dataclass(frozen=True)
class Port:
    number: int
    proto: Proto
    service: str = ""
    product: str = ""
    version: str = ""
    state: str = "open"


@dataclass
class DiscoveredService:
    port: int
    proto: Proto
    service: str = ""
    product: str = ""
    version: str = ""
    nmap_scripts_output: str = ""
    discovered_at: str = ""


def subnet_of(ip: str, prefix: int = 24) -> str:
    # group a host into its network for the pivot topology (e.g. 10.10.5.23 -> "10.10.5.0/24").
    # Returns "" for anything that isn't a plain IP so a bad token never becomes a graph node.
    try:
        return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
    except ValueError:
        return ""


@dataclass
class DiscoveredHost:
    # a host reached across a pivot (CTF/AD lateral movement). The entry host stays Target; these
    # are the additional hosts found by scanning from a foothold, grouped by subnet for the graph.
    ip: str
    hostname: str = ""
    subnet: str = ""  # "10.10.5.0/24" — filled from ip via subnet_of() when empty
    pivot_source: str = ""  # ip of the host we reached this one THROUGH ("" = entry-reachable)
    os_guess: str = ""
    services: list[DiscoveredService] = field(default_factory=list)
    discovered_at: str = ""
    notes: str = ""

    def __post_init__(self) -> None:
        validate_host(self.ip)  # ip is interpolated into command lines — never let a flag/space in
        if self.hostname:
            validate_host(self.hostname)
        # canonicalize the subnet so a hand-edited/untrusted value ("$(id)/24") can never be stored:
        # keep a provided CIDR only if it's a real network containing our ip, else derive it.
        derived = subnet_of(self.ip)
        if self.subnet:
            try:
                net = ipaddress.ip_network(self.subnet, strict=False)
                if ipaddress.ip_address(self.ip) not in net:
                    self.subnet = derived
            except ValueError:
                self.subnet = derived
        else:
            self.subnet = derived


@dataclass(frozen=True)
class Command:
    module: str
    shell_line: str
    why: str
    expected_runtime_hint: str
    output_file: str
    phase: str = "initial-recon"


@dataclass
class Finding:
    service: str
    title: str
    detail: str = ""
    port: int | None = None
    proto: Proto | None = None
    fields: dict[str, str] = field(default_factory=dict)


@dataclass
class Suggestion:
    text: str
    command_template: str | None = None
    source_pattern: str | None = None
    source_box: str | None = None


@dataclass
class Credential:
    username: str
    secret: str
    secret_type: str = "password"
    domain: str = ""
    source: str = ""
    tested_against: list[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class ScanResults:
    target: Target
    services: list[DiscoveredService] = field(default_factory=list)
