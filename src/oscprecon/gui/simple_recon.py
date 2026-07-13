from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from oscprecon.models import Command, Target
from oscprecon.modules import (
    ike,
    kerberos,
    mongodb,
    mssql,
    mysql,
    netbios,
    nfs,
    ntp,
    postgresql,
    redis,
    smtp,
    snmp,
    tftp,
)
from oscprecon.modules.base import Module

# The read-only, single-shape modules (recon_steps -> parse -> suggest) share one GUI panel + worker
# instead of a bespoke widget each. Each spec supplies the concrete step-builder (its shape differs:
# snmp adds a public MIB walk, tftp fans out GETs over a fixed filename list) as a typed function so
# the base Module (which has no step methods) never needs the attribute. `port` is the discovered
# service port; a module with a port-specific Tier-1 command honours it, not a hardcoded default.


def _smtp_steps(target: Target, port: int) -> list[tuple[Command, str]]:
    return [(s.command, s.tool) for s in smtp.SmtpModule().recon_steps(target)]


def _nfs_steps(target: Target, port: int) -> list[tuple[Command, str]]:
    return [(s.command, s.tool) for s in nfs.NfsModule().recon_steps(target)]


def _snmp_steps(target: Target, port: int) -> list[tuple[Command, str]]:
    module = snmp.SnmpModule()
    steps = [*module.discovery_steps(target), module.walk_step(target)]
    return [(s.command, s.tool) for s in steps]


def _tftp_steps(target: Target, port: int) -> list[tuple[Command, str]]:
    module = tftp.TftpModule()
    steps = [module.enum_step(target), *(module.get_step(target, f) for f in tftp.COMMON_FILES)]
    return [(s.command, s.tool) for s in steps]


def _netbios_steps(target: Target, port: int) -> list[tuple[Command, str]]:
    return [(s.command, s.tool) for s in netbios.NetbiosModule().recon_steps(target)]


def _ike_steps(target: Target, port: int) -> list[tuple[Command, str]]:
    return [(s.command, s.tool) for s in ike.IkeModule().recon_steps(target)]


def _kerberos_steps(target: Target, port: int) -> list[tuple[Command, str]]:
    return [(s.command, s.tool) for s in kerberos.KerberosModule().recon_steps(target)]


def _ntp_steps(target: Target, port: int) -> list[tuple[Command, str]]:
    return [(s.command, s.tool) for s in ntp.NtpModule().recon_steps(target)]


def _redis_steps(target: Target, port: int) -> list[tuple[Command, str]]:
    return [(s.command, s.tool) for s in redis.RedisModule().recon_steps(target)]


def _mongodb_steps(target: Target, port: int) -> list[tuple[Command, str]]:
    return [(s.command, s.tool) for s in mongodb.MongoDbModule().recon_steps(target)]


def _mssql_steps(target: Target, port: int) -> list[tuple[Command, str]]:
    return [(s.command, s.tool) for s in mssql.MssqlModule().recon_steps(target, port)]


def _mysql_steps(target: Target, port: int) -> list[tuple[Command, str]]:
    return [(s.command, s.tool) for s in mysql.MysqlModule().recon_steps(target, port)]


def _postgresql_steps(target: Target, port: int) -> list[tuple[Command, str]]:
    return [(s.command, s.tool) for s in postgresql.PostgresqlModule().recon_steps(target, port)]


@dataclass(frozen=True)
class SimpleReconSpec:
    module: str
    label: str  # Tier-1 button text
    intro: str  # panel intro line
    manual_yaml: Path
    factory: Callable[[], Module]  # for parse() + suggest() (uniform on the base Module)
    steps_fn: Callable[[Target, int], list[tuple[Command, str]]]


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
    "kerberos": SimpleReconSpec(
        "kerberos",
        "Run Kerberos recon (KDC confirm · server time)",
        "Kerberos/AD recon — Tier-1 is credential-free nmap -sV (KDC + clock-skew). User/SPN "
        "enumeration (single-user AS-REP, GetADUsers/GetUserSPNs) are Tier-2 manual follow-ups; "
        "enumeration only, no cracking on-host.",
        _manual(kerberos),
        kerberos.KerberosModule,
        _kerberos_steps,
    ),
    "ntp": SimpleReconSpec(
        "ntp",
        "Run full NTP recon (variables · stratum)",
        "NTP recon — ntpq readlist/sysinfo + ntpdate -q (query only, never sets the clock).",
        _manual(ntp),
        ntp.NtpModule,
        _ntp_steps,
    ),
    "redis": SimpleReconSpec(
        "redis",
        "Run full Redis recon (INFO · CONFIG · CLIENT LIST)",
        "Redis recon — unauth INFO/CONFIG/CLIENT LIST (read-only); default-auth check is Tier-2.",
        _manual(redis),
        redis.RedisModule,
        _redis_steps,
    ),
    "mongodb": SimpleReconSpec(
        "mongodb",
        "Run full MongoDB recon (version · databases · collections)",
        "MongoDB recon — unauth version/databases/collections (read-only); else Tier-2.",
        _manual(mongodb),
        mongodb.MongoDbModule,
        _mongodb_steps,
    ),
    "mssql": SimpleReconSpec(
        "mssql",
        "Run full MSSQL recon (banner · instance · NTLM info)",
        "MSSQL recon — unauth ms-sql-info/ntlm-info banner (read-only); sa checks are Tier-2.",
        _manual(mssql),
        mssql.MssqlModule,
        _mssql_steps,
    ),
    "mysql": SimpleReconSpec(
        "mysql",
        "Run full MySQL recon (banner · version · auth-plugin)",
        "MySQL recon — unauth mysql-info banner (read-only); root default-cred is Tier-2.",
        _manual(mysql),
        mysql.MysqlModule,
        _mysql_steps,
    ),
    "postgresql": SimpleReconSpec(
        "postgresql",
        "Run full PostgreSQL recon (nmap -sV version banner)",
        "PostgreSQL recon — Tier-1 is credential-free nmap -sV version detection only; no login is "
        "attempted. Default-cred (postgres:'' / postgres:postgres) and authed read-only enum are "
        "Tier-2 manual follow-ups.",
        _manual(postgresql),
        postgresql.PostgresqlModule,
        _postgresql_steps,
    ),
}
