from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from oscprecon.models import Command, Target
from oscprecon.modules import ike, netbios, nfs, ntp, smtp, snmp, tftp
from oscprecon.modules.base import Module

# The read-only, single-shape modules (recon_steps -> parse -> suggest) share one GUI panel + worker
# instead of a bespoke widget each. Each spec supplies the concrete step-builder (its shape differs:
# snmp adds a public MIB walk, tftp fans out GETs over a fixed filename list) as a typed function so
# the base Module (which has no step methods) never needs the attribute.


def _smtp_steps(target: Target) -> list[tuple[Command, str]]:
    return [(s.command, s.tool) for s in smtp.SmtpModule().recon_steps(target)]


def _nfs_steps(target: Target) -> list[tuple[Command, str]]:
    return [(s.command, s.tool) for s in nfs.NfsModule().recon_steps(target)]


def _snmp_steps(target: Target) -> list[tuple[Command, str]]:
    module = snmp.SnmpModule()
    steps = [*module.discovery_steps(target), module.walk_step(target)]
    return [(s.command, s.tool) for s in steps]


def _tftp_steps(target: Target) -> list[tuple[Command, str]]:
    module = tftp.TftpModule()
    steps = [module.enum_step(target), *(module.get_step(target, f) for f in tftp.COMMON_FILES)]
    return [(s.command, s.tool) for s in steps]


def _netbios_steps(target: Target) -> list[tuple[Command, str]]:
    return [(s.command, s.tool) for s in netbios.NetbiosModule().recon_steps(target)]


def _ike_steps(target: Target) -> list[tuple[Command, str]]:
    return [(s.command, s.tool) for s in ike.IkeModule().recon_steps(target)]


def _ntp_steps(target: Target) -> list[tuple[Command, str]]:
    return [(s.command, s.tool) for s in ntp.NtpModule().recon_steps(target)]


@dataclass(frozen=True)
class SimpleReconSpec:
    module: str
    label: str  # Tier-1 button text
    intro: str  # panel intro line
    manual_yaml: Path
    factory: Callable[[], Module]  # for parse() + suggest() (uniform on the base Module)
    steps_fn: Callable[[Target], list[tuple[Command, str]]]


def _manual(pkg: object) -> Path:
    module_file = getattr(pkg, "__file__", None)
    assert module_file is not None
    return Path(module_file).parent / "manual_commands.yaml"


SIMPLE_SPECS: dict[str, SimpleReconSpec] = {
    "smtp": SimpleReconSpec(
        "smtp",
        "Run full SMTP recon (banner · verbs · open-relay · NTLM)",
        "SMTP recon — read-only NSE fingerprint; VRFY/EXPN user enum is a Tier-2 follow-up.",
        _manual(smtp),
        smtp.SmtpModule,
        _smtp_steps,
    ),
    "nfs": SimpleReconSpec(
        "nfs",
        "Run full NFS recon (exports · bounded nfs-ls)",
        "NFS recon — showmount + nmap nfs-ls (no local mount); mounting is a Tier-2 follow-up.",
        _manual(nfs),
        nfs.NfsModule,
        _nfs_steps,
    ),
    "snmp": SimpleReconSpec(
        "snmp",
        "Run full SNMP recon (community enum · MIB walk)",
        "SNMP recon — onesixtyone (small community list) + nmap NSE + snmpwalk (public).",
        _manual(snmp),
        snmp.SnmpModule,
        _snmp_steps,
    ),
    "tftp": SimpleReconSpec(
        "tftp",
        "Run full TFTP recon (enum · GET well-known files)",
        "TFTP recon — nmap tftp-enum + GET a small list of well-known files (never uploads).",
        _manual(tftp),
        tftp.TftpModule,
        _tftp_steps,
    ),
    "netbios": SimpleReconSpec(
        "netbios",
        "Run full NetBIOS recon (name table)",
        "NetBIOS-NS recon — nmblookup -A + nbtscan (host, domain, roles, MAC).",
        _manual(netbios),
        netbios.NetbiosModule,
        _netbios_steps,
    ),
    "ike": SimpleReconSpec(
        "ike",
        "Run full IKE recon (VPN · aggressive-mode check)",
        "IKE/ISAKMP recon — ike-scan detection + aggressive-mode check; no PSK capture.",
        _manual(ike),
        ike.IkeModule,
        _ike_steps,
    ),
    "ntp": SimpleReconSpec(
        "ntp",
        "Run full NTP recon (variables · stratum)",
        "NTP recon — ntpq readlist/sysinfo + ntpdate -q (query only, never sets the clock).",
        _manual(ntp),
        ntp.NtpModule,
        _ntp_steps,
    ),
}
