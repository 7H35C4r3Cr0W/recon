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
