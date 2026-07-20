from __future__ import annotations

import ipaddress
import re
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
    only_open: bool = False  # --open (hide closed/filtered ports)
    os_detect: bool = False  # -O (OS fingerprint — needs root)
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
    # hostnames are case-insensitive — 'ACTIVE.HTB' is the same entry as 'active.htb'
    if text == entry_ip or (entry_hostname and text.casefold() == entry_hostname.casefold()):
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
        # a -sV scan (carries product) gives the authoritative service name — let it override a bare
        # port-table guess ('http-proxy' -> 'http'), not just fill a blank (mirrors #21 in nmap.py).
        if svc.service and (svc.product or cur.service in ("", "unknown")):
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


# nmap flags that write to (or read commands from) the filesystem — a structured field must never
# smuggle these in and clobber a file. -oN/-oA/-oG/-oX/-oS, --stylesheet, --resume, --datadir,
# --script-args-file, -iL/-iR (input-list). The raw-edit escape hatch still allows them explicitly.
_UNSAFE_LONG_FLAGS = frozenset(
    {"--stylesheet", "--resume", "--datadir", "--script-args-file", "--script-help", "--webxml"}
)


def _reject_unsafe_field(field: str, value: str) -> None:
    if re.search(r"[;&|`$><\n]", value):  # shell metachars have no place in a structured flag field
        raise ValueError(f"{field} contains a shell metacharacter — use the raw-edit box for that")
    for tok in value.split():
        low = tok.lower()
        if re.match(r"^-o[naxgs]", low) or low in ("-il", "-ir") or low in _UNSAFE_LONG_FLAGS:
            raise ValueError(
                f"{field} contains a file-writing nmap flag ({tok}) — use the raw-edit box for that"
            )


# port set / timing per scan profile for a whole-network (CIDR) Run Recon — a versioned sweep across
# the range that streams each live host into the topology. Mirrors modules/nmap.py's single-host
# battery intent (quick=triage … full=everything) but in ONE range pass so a /24 fills the graph.
_NETWORK_PROFILE = {
    "quick": {"ports": "--top-ports 100", "timing": "-T4", "extra": ""},
    "default": {"ports": "--top-ports 1000", "timing": "-T4", "extra": ""},
    "exam": {"ports": "--top-ports 1000", "timing": "-T4", "extra": "--min-rate 1000"},
    "full": {"ports": "-p-", "timing": "-T4", "extra": ""},
}


def network_scan_command(cidr: str, scan_profile: str = "default") -> str:
    # Build the whole-/24 Run-Recon command. -sV (version) so each host lands with product/version;
    # connect scan works unprivileged and through a ligolo/SOCKS pivot. Validated via ScanSpec.
    profile = _NETWORK_PROFILE.get(scan_profile, _NETWORK_PROFILE["default"])
    return build_nmap_command(
        ScanSpec(
            target=cidr,
            scan_type="connect",
            ports=profile["ports"],
            timing=profile["timing"],
            version=True,
            extra=profile["extra"],
        )
    )


def build_nmap_command(spec: ScanSpec) -> str:
    target = validate_scan_target(spec.target)
    _reject_unsafe_field("ports", spec.ports)
    _reject_unsafe_field("scripts", spec.scripts)
    _reject_unsafe_field("extra", spec.extra)
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
        if spec.os_detect:
            tokens.append("-O")
        if spec.only_open:
            tokens.append("--open")
    if spec.extra.strip():
        tokens.append(spec.extra.strip())
    tokens.append(target)
    return " ".join(tokens)
