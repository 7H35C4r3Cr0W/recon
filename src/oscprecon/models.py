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


def is_cidr_range(value: str) -> bool:
    # a CIDR with more than one address (a whole /24 project). A /32 or /128 is a single host
    # written as CIDR, so it is NOT a range.
    text = value.strip()
    if "/" not in text or text.startswith("-") or any(ch.isspace() for ch in text):
        return False
    try:
        return ipaddress.ip_network(text, strict=False).num_addresses > 1
    except ValueError:
        return False


def validate_host_or_range(value: str) -> str:
    # a project target may be a single IP / hostname OR a whole CIDR range (e.g. 10.10.5.0/24). The
    # value is interpolated into command lines and shlex-split, so it must never become a separate
    # argv token — same guard as validate_host, plus a strict CIDR path. A range is normalized to
    # network address so the graph/subnet label is clean (10.10.5.7/24 -> 10.10.5.0/24).
    text = value.strip()
    if not text or text.startswith("-") or any(ch.isspace() for ch in text):
        raise ValueError(f"invalid target: {value!r}")
    if "/" in text:
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError as exc:
            raise ValueError(f"invalid target range: {value!r}") from exc
        # a single-host CIDR (/32, /128) is a HOST, not a range — return the bare address so it
        # flows into {target} tokens cleanly (else "10.10.10.5/32" corrupts every built command).
        if network.num_addresses == 1:
            return str(network.network_address)
        return str(network)
    return validate_host(text)


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
        # ip may be a single host OR a whole CIDR range (a /24 network project). A range never has a
        # hostname (there's no single host to name); host-based recon doesn't apply to a network —
        # so drop any hostname on a range, keeping every construction path (New Project, Edit, load)
        # consistent with Profile.set_target.
        object.__setattr__(self, "ip", validate_host_or_range(self.ip))
        if is_cidr_range(self.ip):
            object.__setattr__(self, "hostname", None)
        elif self.hostname:
            validate_host(self.hostname)

    @property
    def is_range(self) -> bool:
        # a network project (whole /24) rather than a single host — Run Recon does host-discovery
        # across the range into the pivot topology instead of the single-host service battery.
        return is_cidr_range(self.ip)

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
    # nmap port state: "open" (confirmed) or "open|filtered" (UDP no-response — nmap could not
    # confirm it; almost always just a non-responding port). Defaults to "open" so pre-state
    # profiles and hand-built services keep their old confirmed-present behaviour.
    state: str = "open"


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
