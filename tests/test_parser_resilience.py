"""Tool-update resilience: every parser must DEGRADE (return a list, never raise) on drifted output.

A wrapped tool changing its format (new version, truncation, interleaving, garbage) must not crash
the app. This fuzzes every dispatcher with its real tool keys against a battery of malformed inputs.
"""

from collections.abc import Callable

import pytest

from oscprecon.modules.dns.parsers import parse_dns_tool
from oscprecon.modules.ftp.parsers import parse_ftp_listing, parse_ftp_tool
from oscprecon.modules.http.parsers import parse_tool
from oscprecon.modules.ike.parsers import parse_ike_tool
from oscprecon.modules.kerberos.parsers import parse_kerberos_tool
from oscprecon.modules.ldap.parsers import parse_ldap_tool
from oscprecon.modules.mongodb.parsers import parse_mongo_tool
from oscprecon.modules.mssql.parsers import parse_mssql_tool
from oscprecon.modules.mysql.parsers import parse_mysql_tool
from oscprecon.modules.netbios.parsers import parse_netbios_tool
from oscprecon.modules.nfs.parsers import parse_nfs_tool
from oscprecon.modules.ntp.parsers import parse_ntp_tool
from oscprecon.modules.postgresql.parsers import parse_postgresql_tool
from oscprecon.modules.redis.parsers import parse_redis_tool
from oscprecon.modules.smb.parsers import parse_smb_tool
from oscprecon.modules.smtp.parsers import parse_smtp_tool
from oscprecon.modules.snmp.parsers import parse_snmp_tool
from oscprecon.modules.ssh.parsers import parse_ssh_tool
from oscprecon.modules.tftp.parsers import parse_tftp_tool
from oscprecon.modules.vhost.parsers import parse_vhost_tool

# control/binary-ish bytes built at runtime (a null-byte literal can't live in a .py source file)
_CONTROL = "".join(chr(c) for c in (0, 1, 9, 127, 200)) + " control/binary bytes mixed with text"

# malformed / drifted outputs a parser might see if a tool updates or a capture is corrupt.
MALFORMED: list[str] = [
    "",
    "   \n\n \t ",
    "totally unexpected output, not the format at all !!! 12345",
    "{",  # truncated JSON
    '{"results": "not-a-list"}',  # wrong-typed JSON
    '{"results": [{"input": 123, "status": "abc", "length": "xx"}]}',  # wrong field types
    "col_a col_b\n" + "Z" * 8000,  # one absurdly long line
    "445/tcp open\n| header:\n|_ truncated mid",  # truncated nmap script block
    "NEW v9.9 FORMAT\nUnexpected: {weird|pipes}\n[section]\nrow with, wrong; delims",
    _CONTROL,
    "user:pass\n" * 500,  # many lines
]

# dispatcher label -> a callable of (text) using a REAL tool key for that module.
_CASES: dict[str, Callable[[str], list[object]]] = {}


def _add(module: str, fn: Callable[..., list[object]], keys: list[str], **extra: object) -> None:
    for key in keys:
        _CASES[f"{module}:{key}"] = lambda text, k=key: fn(k, text, *extra.values())


_add("dns", parse_dns_tool, ["dig-axfr", "dig-version", "dnsrecon", "nmap-dns"])
_add("ftp", parse_ftp_tool, ["curl-list", "nmap-ftp"])
_add(
    "http",
    parse_tool,
    ["dirsearch", "feroxbuster", "ffuf", "gobuster", "nikto", "whatweb", "wpscan"],
    port=80,
)
_add("ike", parse_ike_tool, ["ike-scan", "ike-scan-aggressive"])
_add("kerberos", parse_kerberos_tool, ["getadusers", "getnpusers", "getuserspns", "nmap-kerberos"])
_add("ldap", parse_ldap_tool, ["ldapsearch-rootdse", "ldapsearch-users", "nmap-ldap"])
_add("mongodb", parse_mongo_tool, ["mongodb-collections", "mongodb-databases", "mongodb-version"])
_add("mssql", parse_mssql_tool, ["mssql-info"])
_add("mysql", parse_mysql_tool, ["mysql-info"])
_add("netbios", parse_netbios_tool, ["nbtscan", "nmblookup"])
_add("nfs", parse_nfs_tool, ["nmap-nfs", "showmount", "ls"])
_add("ntp", parse_ntp_tool, ["ntpdate", "ntpq-readlist", "ntpq-sysinfo"])
_add("postgresql", parse_postgresql_tool, ["postgresql-sv"])
_add("redis", parse_redis_tool, ["redis-clients", "redis-config", "redis-info"])
_add(
    "smb",
    parse_smb_tool,
    [
        "netexec-shares",
        "netexec-users",
        "netexec-passpol",
        "netexec-ridbrute",
        "rpcclient-users",
        "smbclient-shares",
    ],
)
_add("smtp", parse_smtp_tool, ["nmap-smtp"])
_add("snmp", parse_snmp_tool, ["nmap-snmp", "onesixtyone", "snmpwalk"])
_add("ssh", parse_ssh_tool, ["nmap-ssh"])
_add("tftp", parse_tftp_tool, ["nmap-tftp"])
_add(
    "vhost",
    parse_vhost_tool,
    ["ffuf", "gobuster", "gobuster-vhost", "gobuster-dns", "dnsrecon", "wfuzz"],
    domain="example.com",
)


@pytest.mark.parametrize("label", sorted(_CASES))
def test_parser_degrades_on_malformed_output(label: str) -> None:
    parse = _CASES[label]
    for bad in MALFORMED:
        result = parse(bad)
        assert isinstance(result, list), f"{label} returned non-list"


def test_ftp_listing_degrades() -> None:
    for bad in MALFORMED:
        assert isinstance(parse_ftp_listing(bad), list)


def test_run_parser_contains_a_raising_parser() -> None:
    from oscprecon.parsing import run_parser

    def boom() -> list[object]:
        raise ValueError("tool changed its output format")

    lines: list[str] = []
    result = run_parser(boom, label="smb netexec-shares", on_line=lines.append)
    assert result == []  # contained, not raised
    assert lines and "couldn't parse" in lines[0] and "smb netexec-shares" in lines[0]


def test_run_parser_passes_through_success() -> None:
    from oscprecon.parsing import run_parser

    assert run_parser(lambda: [1, 2, 3], label="x") == [1, 2, 3]
