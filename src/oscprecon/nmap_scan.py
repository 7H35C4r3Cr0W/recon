from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from oscprecon.models import DiscoveredService, Proto, validate_host

# Build an nmap command from a structured spec (the "Scan…" dialog) so the user has real control
# over the scan — connect vs SYN vs UDP vs ping-sweep, -Pn for hosts that drop the ping/handshake,
# ports, timing, version/scripts, plus a free-form flags box for anything not exposed. The dialog
# also offers a raw-edit escape hatch, so this is a convenience builder, not the only path. The
# shell chokepoint (`shell.policy_violation`) remains the exec gate; nmap allows any flag except
# `--script *brute*`, so custom flags flow through.

_SCAN_TYPE_FLAG = {
    "connect": "-sT",  # TCP connect — no raw sockets, works unprivileged / through many tunnels
    "syn": "-sS",  # SYN (half-open) — faster, needs root
    "udp": "-sU",  # UDP
    "ping": "-sn",  # host discovery only (ping sweep) — no port scan
}


@dataclass
class ScanSpec:
    target: str  # a single IP/hostname or a CIDR range (e.g. 10.10.5.0/24)
    scan_type: str = "connect"  # connect | syn | udp | ping
    no_ping: bool = False  # -Pn (treat host as up; skip discovery)
    ports: str = "--top-ports 1000"  # free-form port spec ("-p-", "-p 22,80", "--top-ports 1000")
    timing: str = "-T4"  # -T0..-T5 (or "")
    version: bool = True  # -sV
    default_scripts: bool = False  # -sC
    scripts: str = ""  # NSE scripts -> --script <scripts>
    extra: str = ""  # free-form extra flags (full power)


def validate_scan_target(target: str) -> str:
    # target is interpolated into the command line and shlex-split, so reject anything that could
    # become a separate argv token. Accept a single IP/hostname or a CIDR range.
    text = target.strip()
    if not text or text.startswith("-") or any(ch.isspace() for ch in text):
        raise ValueError(f"invalid scan target: {target!r}")
    if "/" in text:
        ipaddress.ip_network(text, strict=False)  # raises ValueError on a malformed CIDR
        return text
    validate_host(text)  # a plain IP or a strict hostname
    return text


def is_entry_target(target: str, entry_ip: str, entry_hostname: str = "") -> bool:
    # is this scan aimed at the profile's entry host (so results are discovered_services, not a
    # pivoted host)? Accept the bare IP, the entry hostname, or the entry IP written as /32 — not
    # just an exact string match, so re-spelling the entry doesn't misroute + drop the results.
    text = target.strip()
    if text == entry_ip or (entry_hostname and text == entry_hostname):
        return True
    if "/" in text:
        try:
            net = ipaddress.ip_network(text, strict=False)
        except ValueError:
            return False
        return net.num_addresses == 1 and str(net.network_address) == entry_ip
    return False


def merge_services(
    existing: list[DiscoveredService], new: list[DiscoveredService]
) -> list[DiscoveredService]:
    # union by (port, proto): a custom/narrower entry re-scan must ADD to, never REPLACE, prior
    # discovery — else a top-1000 TCP re-scan would wipe UDP + high TCP ports found by an earlier
    # full sweep. Mirrors NmapModule.discovered_services' merge: fill blank product/version/service
    # from the newer scan, keep the older port when the new scan didn't cover it.
    merged: dict[tuple[int, Proto], DiscoveredService] = {(s.port, s.proto): s for s in existing}
    for svc in new:
        key = (svc.port, svc.proto)
        cur = merged.get(key)
        if cur is None:
            merged[key] = svc
            continue
        if svc.product and not cur.product:
            cur.product = svc.product
        if svc.version and not cur.version:
            cur.version = svc.version
        if svc.service and cur.service in ("", "unknown"):
            cur.service = svc.service
        if svc.nmap_scripts_output and not cur.nmap_scripts_output:
            cur.nmap_scripts_output = svc.nmap_scripts_output
    return sorted(merged.values(), key=lambda s: (s.proto.value, s.port))


def is_range(target: str) -> bool:
    # a CIDR with more than one address is a range (a /32 or /128 is a single host written as CIDR)
    if "/" not in target:
        return False
    try:
        return ipaddress.ip_network(target.strip(), strict=False).num_addresses > 1
    except ValueError:
        return False


def build_nmap_command(spec: ScanSpec) -> str:
    target = validate_scan_target(spec.target)
    tokens: list[str] = ["nmap"]
    ping_sweep = spec.scan_type == "ping"
    tokens.append(_SCAN_TYPE_FLAG.get(spec.scan_type, "-sT"))
    if spec.no_ping and not ping_sweep:  # -Pn is meaningless with -sn (both concern discovery)
        tokens.append("-Pn")
    if spec.timing.strip():
        tokens.append(spec.timing.strip())
    if not ping_sweep:
        # a ping sweep discovers live hosts only — ports / version / scripts do not apply
        if spec.ports.strip():
            tokens.append(spec.ports.strip())
        if spec.version:
            tokens.append("-sV")
        if spec.default_scripts:
            tokens.append("-sC")
        if spec.scripts.strip():
            tokens.append(f"--script {spec.scripts.strip()}")
    if spec.extra.strip():
        tokens.append(spec.extra.strip())
    tokens.append(target)
    return " ".join(tokens)
