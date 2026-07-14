from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from oscprecon.models import Command, Target
from oscprecon.modules import (
    ajp,
    couchdb,
    docker,
    elasticsearch,
    finger,
    ike,
    ipmi,
    kerberos,
    kubernetes,
    memcached,
    mongodb,
    mssql,
    mysql,
    netbios,
    nfs,
    ntp,
    oracle,
    postgresql,
    rdp,
    redis,
    sip,
    smtp,
    snmp,
    tftp,
    vnc,
    x11,
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


def _rdp_steps(target: Target, port: int) -> list[tuple[Command, str]]:
    return [(s.command, s.tool) for s in rdp.RdpModule().recon_steps(target, port)]


def _vnc_steps(target: Target, port: int) -> list[tuple[Command, str]]:
    return [(s.command, s.tool) for s in vnc.VncModule().recon_steps(target, port)]


def _finger_steps(target: Target, port: int) -> list[tuple[Command, str]]:
    return [(s.command, s.tool) for s in finger.FingerModule().recon_steps(target, port)]


def _x11_steps(target: Target, port: int) -> list[tuple[Command, str]]:
    return [(s.command, s.tool) for s in x11.X11Module().recon_steps(target, port)]


def _ajp_steps(target: Target, port: int) -> list[tuple[Command, str]]:
    return [(s.command, s.tool) for s in ajp.AjpModule().recon_steps(target, port)]


def _ipmi_steps(target: Target, port: int) -> list[tuple[Command, str]]:
    return [(s.command, s.tool) for s in ipmi.IpmiModule().recon_steps(target, port)]


def _sip_steps(target: Target, port: int) -> list[tuple[Command, str]]:
    return [(s.command, s.tool) for s in sip.SipModule().recon_steps(target, port)]


def _oracle_steps(target: Target, port: int) -> list[tuple[Command, str]]:
    return [(s.command, s.tool) for s in oracle.OracleModule().recon_steps(target, port)]


def _elasticsearch_steps(target: Target, port: int) -> list[tuple[Command, str]]:
    return [
        (s.command, s.tool) for s in elasticsearch.ElasticsearchModule().recon_steps(target, port)
    ]


def _couchdb_steps(target: Target, port: int) -> list[tuple[Command, str]]:
    return [(s.command, s.tool) for s in couchdb.CouchdbModule().recon_steps(target, port)]


def _docker_steps(target: Target, port: int) -> list[tuple[Command, str]]:
    return [(s.command, s.tool) for s in docker.DockerModule().recon_steps(target, port)]


def _kubernetes_steps(target: Target, port: int) -> list[tuple[Command, str]]:
    return [(s.command, s.tool) for s in kubernetes.KubernetesModule().recon_steps(target, port)]


def _memcached_steps(target: Target, port: int) -> list[tuple[Command, str]]:
    return [(s.command, s.tool) for s in memcached.MemcachedModule().recon_steps(target, port)]


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
    "rdp": SimpleReconSpec(
        "rdp",
        "Run full RDP recon (NTLM info · NLA · encryption)",
        "RDP recon — unauth rdp-ntlm-info (AD domain/host/OS build) + rdp-enum-encryption (NLA "
        "state); read-only, no login. Credential testing is Spray-mode only.",
        _manual(rdp),
        rdp.RdpModule,
        _rdp_steps,
    ),
    "vnc": SimpleReconSpec(
        "vnc",
        "Run full VNC recon (version · auth types · desktop)",
        "VNC recon — unauth vnc-info (RFB version + offered security types) + vnc-title (desktop "
        "name); read-only. A 'None' security type means an open display. Password guessing is off.",
        _manual(vnc),
        vnc.VncModule,
        _vnc_steps,
    ),
    "finger": SimpleReconSpec(
        "finger",
        "Run full Finger recon (logged-in users)",
        "Finger recon — finger @{target} + nmap finger NSE disclose system usernames (read-only). "
        "Wordlist user-enumeration is Tier-3 and never wrapped.",
        _manual(finger),
        finger.FingerModule,
        _finger_steps,
    ),
    "x11": SimpleReconSpec(
        "x11",
        "Run full X11 recon (open-display check)",
        "X11 recon — x11-access tests whether the X server (:0-:9) grants unauthenticated access; "
        "read-only, no screen capture. An open display is flagged as an exposure.",
        _manual(x11),
        x11.X11Module,
        _x11_steps,
    ),
    "ajp": SimpleReconSpec(
        "ajp",
        "Run full AJP recon (methods · headers)",
        "AJP13 recon — ajp-methods (allowed HTTP methods) + ajp-headers (Server banner) on the "
        "Tomcat AJP connector; read-only. The Ghostcat CVE is not wrapped.",
        _manual(ajp),
        ajp.AjpModule,
        _ajp_steps,
    ),
    "ipmi": SimpleReconSpec(
        "ipmi",
        "Run full IPMI recon (version · cipher-zero)",
        "IPMI recon (UDP) — ipmi-version (IPMI/auth levels) + ipmi-cipher-zero (auth-bypass "
        "misconfig detection); read-only. RAKP hash retrieval is out of scope.",
        _manual(ipmi),
        ipmi.IpmiModule,
        _ipmi_steps,
    ),
    "sip": SimpleReconSpec(
        "sip",
        "Run full SIP recon (methods · server banner)",
        "SIP recon (UDP) — sip-methods (accepted verbs) + Server/User-Agent banner; read-only. "
        "Extension enumeration (svwar) is list-based and out of scope.",
        _manual(sip),
        sip.SipModule,
        _sip_steps,
    ),
    "oracle": SimpleReconSpec(
        "oracle",
        "Run full Oracle recon (TNS listener version)",
        "Oracle recon — oracle-tns-version reads the TNS listener version (read-only, no login). "
        "A valid SID is needed before auth; SID enumeration is a Tier-2 follow-up.",
        _manual(oracle),
        oracle.OracleModule,
        _oracle_steps,
    ),
    "elasticsearch": SimpleReconSpec(
        "elasticsearch",
        "Run full Elasticsearch recon (version · indices · health)",
        "Elasticsearch recon — unauth curl of / (version), _cat/indices (index list), and "
        "_cluster/health; read-only. A secured cluster answers 401 and no data is leaked.",
        _manual(elasticsearch),
        elasticsearch.ElasticsearchModule,
        _elasticsearch_steps,
    ),
    "couchdb": SimpleReconSpec(
        "couchdb",
        "Run full CouchDB recon (version · databases · nodes)",
        "CouchDB recon — unauth curl of / (version), _all_dbs (database list), and _membership; "
        "read-only. A list returned without a 401 means 'admin party' (no auth).",
        _manual(couchdb),
        couchdb.CouchdbModule,
        _couchdb_steps,
    ),
    "docker": SimpleReconSpec(
        "docker",
        "Run full Docker API recon (version · info · containers)",
        "Docker remote-API recon — unauth curl of /version, /info, /containers/json; read-only GET "
        "endpoints only. An unauthenticated daemon is full host control; exec is never run.",
        _manual(docker),
        docker.DockerModule,
        _docker_steps,
    ),
    "kubernetes": SimpleReconSpec(
        "kubernetes",
        "Run full Kubernetes recon (version · anon API · health)",
        "Kubernetes API recon — curl -k of /version, /api (anonymous-access check), and /healthz; "
        "read-only GETs. Pod exec / creating workloads is never issued.",
        _manual(kubernetes),
        kubernetes.KubernetesModule,
        _kubernetes_steps,
    ),
    "memcached": SimpleReconSpec(
        "memcached",
        "Run full Memcached recon (version · items · stats)",
        "Memcached recon — nmap memcached-info dumps version + slab/item stats over the text "
        "protocol (unauth read-only). No SET/DELETE/FLUSH is ever issued.",
        _manual(memcached),
        memcached.MemcachedModule,
        _memcached_steps,
    ),
}
