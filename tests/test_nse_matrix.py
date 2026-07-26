from __future__ import annotations

import dataclasses
import fnmatch
import re
from pathlib import Path

import pytest

from oscprecon import nse_matrix
from oscprecon.nse_matrix import MATRIX, ServiceScripts, for_service

SCRIPT_DB = Path("/usr/share/nmap/scripts/script.db")

# The rows in the OT/ICS/IoT band. Every one of them must carry fragile=True: these speak to PLCs,
# building controllers and field instruments, where even a read-only discovery probe is traffic
# into live plant.
OT_KEYS = frozenset(
    {
        "modbus",
        "s7",
        "bacnet",
        "enip",
        "dnp3",
        "iec61850",
        "coap",
        "knx",
        "hartip",
        "omron",
        "profinet",
        "mqtt",
    }
)


def _installed_scripts() -> list[str]:
    entries = re.findall(r'filename\s*=\s*"([^"]+)\.nse"', SCRIPT_DB.read_text(encoding="utf-8"))
    assert entries, "script.db parsed to nothing — the Entry format changed"
    return entries


def _resolves(prefix: str, scripts: list[str]) -> list[str]:
    return [s for s in scripts if fnmatch.fnmatch(s, prefix)]


# --- the prefixes must actually exist -----------------------------------------------------------


@pytest.mark.skipif(not SCRIPT_DB.exists(), reason="nmap script.db not installed")
def test_every_prefix_resolves_to_at_least_one_installed_script() -> None:
    # a prefix matching nothing is not a no-op: nmap exits with "did not match a category,
    # filename, or directory" and the whole scan dies before a single probe goes out
    scripts = _installed_scripts()
    dead = [
        (entry.key, prefix)
        for entry in MATRIX
        for prefix in entry.prefixes
        if not _resolves(prefix, scripts)
    ]
    assert not dead, f"dead NSE prefixes — nmap would error out: {dead}"


@pytest.mark.skipif(not SCRIPT_DB.exists(), reason="nmap script.db not installed")
def test_header_prefix_counts_match_script_db() -> None:
    # the module header publishes a prefix -> count table; re-derive it so it is checkable
    # rather than a claim that quietly rots when nmap ships a new script
    scripts = _installed_scripts()
    source = Path(nse_matrix.__file__).read_text(encoding="utf-8")
    table = source.split("PREFIX -> INSTALLED SCRIPT COUNT", 1)[1].split("\n#\n", 1)[0]
    claimed = dict(re.findall(r"([A-Za-z0-9][A-Za-z0-9.*_-]*)\s+(\d+)", table))
    assert len(claimed) > 50, "header count table did not parse"

    used = {prefix for entry in MATRIX for prefix in entry.prefixes}
    assert used <= set(claimed), f"prefixes missing from the header table: {used - set(claimed)}"
    wrong = {
        prefix: (int(count), len(_resolves(prefix, scripts)))
        for prefix, count in claimed.items()
        if int(count) != len(_resolves(prefix, scripts))
    }
    assert not wrong, f"header claims (claimed, actual): {wrong}"


@pytest.mark.skipif(not SCRIPT_DB.exists(), reason="nmap script.db not installed")
def test_dropped_prefixes_really_are_dead() -> None:
    # the header names four prefixes dropped for resolving to nothing — if a future nmap ships
    # them, the header is wrong and the rows should get their scripts back
    scripts = _installed_scripts()
    for prefix in ("zookeeper-*", "radius-*", "dnp3-*", "rsh-*"):
        assert not _resolves(prefix, scripts), f"{prefix} now exists — restore it to the matrix"


# --- shape of the data --------------------------------------------------------------------------


def test_keys_are_unique_and_identifier_safe() -> None:
    keys = [entry.key for entry in MATRIX]
    assert len(keys) == len(set(keys)), "duplicate service key"
    for key in keys:
        assert key.isidentifier(), f"{key!r} is not a valid Python identifier fragment"
        assert key == key.lower(), f"{key!r} should be lowercase"


def test_names_are_unique_across_rows() -> None:
    # a name claimed twice means one row silently shadows the other in the lookup index
    seen: dict[str, str] = {}
    for entry in MATRIX:
        for name in entry.names:
            lowered = name.lower()
            assert lowered not in seen, (
                f"{name!r} claimed by both {seen.get(lowered)} and {entry.key}"
            )
            seen[lowered] = entry.key


def test_every_row_is_identifiable() -> None:
    # a row with no ports and no names can never be reached; `tls` is the one deliberate
    # exception — it is the set a caller layers onto any port -sV reported as ssl/…
    for entry in MATRIX:
        if entry.key == "tls":
            continue
        assert entry.tcp_ports or entry.udp_ports or entry.names, f"{entry.key} is unreachable"


def test_every_row_carries_a_note() -> None:
    for entry in MATRIX:
        assert entry.note.strip(), f"{entry.key} has no operator note"
        assert entry.label.strip(), f"{entry.key} has no label"


def test_ports_are_plausible() -> None:
    for entry in MATRIX:
        for port in (*entry.tcp_ports, *entry.udp_ports):
            assert 1 <= port <= 65535, f"{entry.key}: {port} is not a port"


def test_by_key_index_covers_the_matrix() -> None:
    assert set(nse_matrix.BY_KEY) == {entry.key for entry in MATRIX}


# --- fragile / OT band ---------------------------------------------------------------------------


def test_every_ot_ics_row_is_fragile() -> None:
    for key in OT_KEYS:
        entry = nse_matrix.BY_KEY[key]
        assert entry.fragile, f"{key} is OT/ICS and must be marked fragile"


def test_nothing_outside_the_ot_band_is_marked_fragile() -> None:
    marked = {entry.key for entry in MATRIX if entry.fragile}
    assert marked == OT_KEYS, f"unexpected fragile rows: {marked ^ OT_KEYS}"


# --- for_service: name first, port second --------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "port", "key"),
    [
        ("microsoft-ds", 445, "smb"),
        ("netbios-ssn", 139, "smb"),
        ("netbios-ns", 137, "netbios"),
        ("msrpc", 135, "msrpc"),
        ("ms-wbt-server", 3389, "rdp"),
        ("wsman", 5985, "winrm"),
        ("wsmans", 5986, "winrm_https"),
        ("ldap", 389, "ldap"),
        ("ldapssl", 636, "ldaps"),
        ("globalcatLDAP", 3268, "globalcat"),
        ("kerberos-sec", 88, "kerberos"),
        ("domain", 53, "dns"),
        ("ftp", 21, "ftp"),
        ("ssh", 22, "ssh"),
        ("telnet", 23, "telnet"),
        ("tftp", 69, "tftp"),
        ("rsync", 873, "rsync"),
        ("afp", 548, "afp"),
        ("rpcbind", 111, "rpcbind"),
        ("nfs", 2049, "nfs"),
        ("vnc", 5900, "vnc"),
        ("x11", 6000, "x11"),
        ("iscsi", 3260, "iscsi"),
        ("http", 80, "http"),
        ("http-proxy", 8080, "http"),
        ("https", 443, "https"),
        ("ajp13", 8009, "ajp"),
        ("squid-http", 3128, "proxy"),
        ("smtp", 25, "smtp"),
        ("submission", 587, "submission"),
        ("pop3", 110, "pop3"),
        ("imaps", 993, "imaps"),
        ("nntp", 119, "nntp"),
        ("ms-sql-s", 1433, "mssql"),
        ("ms-sql-m", 1434, "mssql"),
        ("mysql", 3306, "mysql"),
        ("postgresql", 5432, "postgresql"),
        ("oracle-tns", 1521, "oracle"),
        ("ibm-db2", 50000, "db2"),
        ("mongod", 27017, "mongodb"),
        ("redis", 6379, "redis"),
        ("couchdb", 5984, "couchdb"),
        ("memcache", 11211, "memcached"),
        ("docker", 2375, "docker"),
        ("amqp", 5672, "amqp"),
        ("mqtt", 1883, "mqtt"),
        ("isakmp", 500, "ike"),
        ("snmp", 161, "snmp"),
        ("ntp", 123, "ntp"),
        ("asf-rmcp", 623, "ipmi"),
        ("sip", 5060, "sip"),
        ("rtsp", 554, "rtsp"),
        ("upnp", 1900, "upnp"),
        ("llmnr", 5355, "llmnr"),
        ("mdns", 5353, "mdns"),
        ("ipp", 631, "ipp"),
        ("jetdirect", 9100, "jetdirect"),
        ("tacacs", 49, "tacacs"),
        ("nbd", 10809, "nbd"),
        ("finger", 79, "finger"),
        ("ident", 113, "ident"),
        ("irc", 6667, "irc"),
        ("iso-tsap", 102, "s7"),
        ("bacnet", 47808, "bacnet"),
        ("coap", 5683, "coap"),
    ],
)
def test_for_service_resolves_the_names_it_claims(name: str, port: int, key: str) -> None:
    found = for_service(name, port)
    assert found is not None, f"{name}:{port} resolved to nothing"
    assert found.key == key


@pytest.mark.parametrize(
    ("name", "port", "key"),
    [
        # the operator's rule: trigger on the detected service/product, not on a default port.
        # every one of these is the service running somewhere it "shouldn't" be.
        ("http", 5000, "http"),
        ("http", 31337, "http"),
        ("ftp", 2121, "ftp"),
        ("ssh", 2222, "ssh"),
        ("ssh", 60000, "ssh"),
        ("microsoft-ds", 4445, "smb"),
        ("mysql", 33006, "mysql"),
        ("https", 65000, "https"),
        ("ms-sql-s", 14330, "mssql"),
        ("vnc", 11100, "vnc"),
    ],
)
def test_the_name_beats_a_non_standard_port(name: str, port: int, key: str) -> None:
    found = for_service(name, port)
    assert found is not None and found.key == key


def test_service_name_outranks_the_port_when_they_disagree() -> None:
    # 22 is SSH's port, but if -sV says the thing answering is HTTP, it is HTTP
    found = for_service("http", 22)
    assert found is not None and found.key == "http"


@pytest.mark.parametrize(
    ("name", "product", "key"),
    [
        ("http", "Apache Tomcat/Coyote JSP engine 1.1", "tomcat"),
        ("http", "Jenkins 2.121.1", "jenkins"),
        ("http", "Microsoft IIS httpd 10.0", "iis"),
        ("http", "Apache httpd 2.4.29", "apache"),
        ("http", "Adobe ColdFusion", "coldfusion"),
        ("http", "WordPress 5.4", "wordpress"),
        ("http", "Drupal 7", "drupal"),
        ("http", "Joomla CMS", "joomla"),
        # "Apache CouchDB" must not be swallowed by the "apache httpd" token
        ("http", "Apache CouchDB 3.2.1", "couchdb"),
        ("https", "Kubernetes API server", "kubernetes"),
        ("http", "Elasticsearch REST API 7.9", "elasticsearch"),
        ("http", "Grafana", "grafana"),
        ("http", "Splunkd httpd", "splunk"),
        ("http", "Docker Engine API", "docker"),
    ],
)
def test_the_product_refines_a_generic_web_service(name: str, product: str, key: str) -> None:
    found = for_service(name, 8080, product)
    assert found is not None and found.key == key


def test_a_product_never_overrides_a_specific_service_name() -> None:
    # nmap prints "Apache httpd" as the product of many non-web services' management pages; a row
    # that already identified itself by name must keep it
    found = for_service("ms-sql-s", 1433, "Microsoft SQL Server 2019 15.00.2000")
    assert found is not None and found.key == "mssql"


def test_tunnelled_tls_names_resolve() -> None:
    for name in ("ssl/http", "ssl/https"):
        found = for_service(name, 443)
        assert found is not None and found.key == "https"
    # an ssl/<something> nmap has no row for still falls back to the inner service
    found = for_service("ssl/ftp", 990)
    assert found is not None and found.key in {"ftp", "ftps"}


def test_port_is_the_fallback_when_the_name_says_nothing() -> None:
    for name in ("", "unknown", "tcpwrapped"):
        found = for_service(name, 445)
        assert found is not None and found.key == "smb", name


def test_generic_web_ports_fall_to_http_not_to_an_app_row() -> None:
    # 8080 alone is not Tomcat and not Jenkins — declaring one of those off a bare port number is
    # exactly the false positive the name-first rule exists to prevent
    for port in (80, 8000, 8080, 8888):
        found = for_service("", port)
        assert found is not None and found.key == "http", port


def test_unknown_service_and_unknown_port_resolve_to_nothing() -> None:
    assert for_service("no-such-service", 0) is None
    assert for_service("no-such-service", 64999) is None


def test_lookup_is_case_insensitive_and_whitespace_tolerant() -> None:
    found = for_service("  Microsoft-DS  ", 445)
    assert found is not None and found.key == "smb"


# --- coverage of the operator's matrix ------------------------------------------------------------


def test_the_requested_service_rows_are_all_present() -> None:
    required = {
        "smb",
        "netbios",
        "msrpc",
        "rdp",
        "winrm",
        "winrm_https",
        "ldap",
        "ldaps",
        "globalcat",
        "kerberos",
        "dns",
        "ftp",
        "ftps",
        "ssh",
        "telnet",
        "tftp",
        "rexec",
        "rlogin",
        "rsh",
        "rsync",
        "afp",
        "nfs",
        "rpcbind",
        "vnc",
        "x11",
        "iscsi",
        "http",
        "https",
        "tls",
        "ajp",
        "proxy",
        "tomcat",
        "jenkins",
        "webdav",
        "wordpress",
        "drupal",
        "joomla",
        "iis",
        "apache",
        "coldfusion",
        "smtp",
        "smtps",
        "submission",
        "pop3",
        "pop3s",
        "imap",
        "imaps",
        "nntp",
        "mssql",
        "mysql",
        "postgresql",
        "oracle",
        "db2",
        "mongodb",
        "redis",
        "couchdb",
        "cassandra",
        "memcached",
        "informix",
        "riak",
        "elasticsearch",
        "neo4j",
        "docker",
        "kubernetes",
        "kubelet",
        "k8s_control",
        "etcd",
        "consul",
        "consul_dns",
        "zookeeper",
        "amqp",
        "rabbitmq_mgmt",
        "mqtt",
        "git",
        "svn",
        "prometheus",
        "grafana",
        "splunk",
        "dhcp",
        "ntp",
        "snmp",
        "snmptrap",
        "ipmi",
        "ike",
        "sip",
        "rtsp",
        "upnp",
        "llmnr",
        "mdns",
        "wsd",
        "ipp",
        "jetdirect",
        "radius",
        "tacacs",
        "rpcap",
        "nbd",
        "modbus",
        "s7",
        "bacnet",
        "enip",
        "dnp3",
        "iec61850",
        "coap",
        "knx",
        "hartip",
        "omron",
        "profinet",
    }
    assert required <= set(nse_matrix.BY_KEY), required - set(nse_matrix.BY_KEY)


@pytest.mark.parametrize(
    ("key", "port"),
    [
        ("smb", 445),
        ("netbios", 137),
        ("msrpc", 135),
        ("rdp", 3389),
        ("winrm", 5985),
        ("winrm_https", 5986),
        ("ldaps", 636),
        ("globalcat", 3269),
        ("kerberos", 464),
        ("tftp", 69),
        ("rexec", 512),
        ("rlogin", 513),
        ("rsh", 514),
        ("iscsi", 3260),
        ("ajp", 8009),
        ("nntp", 563),
        ("oracle", 2484),
        ("mongodb", 27019),
        ("cassandra", 9042),
        ("informix", 9088),
        ("riak", 8098),
        ("elasticsearch", 9200),
        ("neo4j", 7687),
        ("kubernetes", 6443),
        ("kubelet", 10250),
        ("k8s_control", 10257),
        ("etcd", 2379),
        ("consul", 8500),
        ("consul_dns", 8600),
        ("zookeeper", 2181),
        ("rabbitmq_mgmt", 15672),
        ("git", 9418),
        ("svn", 3690),
        ("prometheus", 9090),
        ("grafana", 3000),
        ("dhcp", 67),
        ("snmptrap", 162),
        ("ipmi", 623),
        ("ike", 4500),
        ("upnp", 1900),
        ("llmnr", 5355),
        ("mdns", 5353),
        ("wsd", 3702),
        ("ipp", 631),
        ("jetdirect", 9100),
        ("radius", 1812),
        ("tacacs", 49),
        ("rpcap", 2002),
        ("nbd", 10809),
        ("modbus", 502),
        ("bacnet", 47808),
        ("enip", 44818),
        ("dnp3", 20000),
        ("iec61850", 2404),
        ("coap", 5683),
        ("knx", 3671),
        ("hartip", 5094),
        ("omron", 9600),
        ("profinet", 34964),
    ],
)
def test_the_documented_port_resolves_to_its_own_row(key: str, port: int) -> None:
    # every port the operator listed must reach the row that claims it — a port silently swallowed
    # by an earlier row is a service that never gets scanned
    found = for_service("", port)
    assert found is not None and found.key == key, f"{port} went to {found and found.key}"


def test_rows_without_scripts_are_deliberate() -> None:
    # radius and dnp3 have no NSE coverage at all; every other row must offer something to run
    empty = {entry.key for entry in MATRIX if not entry.prefixes}
    assert empty == {"radius", "dnp3"}, empty


def test_fragile_rows_are_reachable_for_a_warning() -> None:
    # the point of fragile is that a caller can warn before scanning — so every fragile row has to
    # be resolvable from something a scan actually produces
    for entry in MATRIX:
        if entry.fragile:
            assert entry.names or entry.tcp_ports or entry.udp_ports, entry.key


def test_dataclass_is_frozen() -> None:
    entry = MATRIX[0]
    assert isinstance(entry, ServiceScripts)
    with pytest.raises(dataclasses.FrozenInstanceError):
        entry.key = "mutated"  # type: ignore[misc]
