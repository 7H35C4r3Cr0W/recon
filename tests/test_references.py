from pathlib import Path

from oscprecon import references
from oscprecon.models import DiscoveredService, Proto

FIXTURES = Path(__file__).parent / "fixtures"


def _svc(
    port: int, proto: Proto, service: str = "", product: str = "", version: str = ""
) -> DiscoveredService:
    return DiscoveredService(
        port=port, proto=proto, service=service, product=product, version=version
    )


def test_services_yaml_loads() -> None:
    rules = references.load_rules()
    assert len(rules) > 40
    # SMB 445 present with tool hints
    smb = references.match(_svc(445, Proto.TCP, "microsoft-ds"))
    assert smb is not None
    assert smb.label == "SMB"
    assert smb.module == "smb"
    assert "pentesting-smb" in smb.hacktricks
    assert any("smbclient" in hint.name for hint in smb.tools)


def test_alt_http_port_maps_to_http_module() -> None:
    ref = references.match(_svc(8080, Proto.TCP, "http-proxy"))
    assert ref is not None
    assert ref.module == "http"


def test_service_name_fallback_for_odd_http_port() -> None:
    # a service on a non-standard port with no port rule still matches by service_name
    ref = references.match(_svc(48291, Proto.TCP, "http"))
    assert ref is not None
    assert ref.module == "http"


def test_specificity_prefers_port_over_service_name() -> None:
    rules = [
        references.MatchRule("generic", "u", "http", [], service_name="http"),
        references.MatchRule("smb", "u", "smb", [], port=445, proto="tcp"),
    ]
    ref = references.match(_svc(445, Proto.TCP, "http"), rules)
    assert ref is not None and ref.module == "smb"


def test_product_override_matches() -> None:
    ref = references.match(_svc(2222, Proto.TCP, "ssh", "OpenSSH", "8.4p1"))
    assert ref is not None
    assert ref.module == "ssh"


def test_dns_udp_maps_to_dns_module() -> None:
    # DNS's primary transport is UDP — 53/udp must reach the dns module/panel, not fall through
    ref = references.match(_svc(53, Proto.UDP, "domain"))
    assert ref is not None
    assert ref.module == "dns"


def test_dns_service_name_fallback_on_odd_port() -> None:
    ref = references.match(_svc(5300, Proto.TCP, "domain"))
    assert ref is not None
    assert ref.module == "dns"


def test_no_match_returns_none() -> None:
    assert references.match(_svc(1, Proto.TCP, "tcpwrapped")) is None


def test_smb_445_and_odd_port_route_to_smb() -> None:
    assert references.match(_svc(445, Proto.TCP, "microsoft-ds")).module == "smb"
    # SMB relocated to a non-standard port still routes via the service-name fallback
    assert references.match(_svc(4445, Proto.TCP, "microsoft-ds")).module == "smb"


def test_https_443_and_ssl_http_alt_port_route_to_http() -> None:
    assert references.match(_svc(443, Proto.TCP, "https")).module == "http"
    assert references.match(_svc(8443, Proto.TCP, "ssl/http")).module == "http"
    assert references.match(_svc(9999, Proto.TCP, "ssl/http")).module == "http"  # odd HTTPS port


def test_database_on_nonstandard_port_routes_via_service_name() -> None:
    # regression: DBs on relocated ports must reach their module (previously fell through to None)
    assert references.match(_svc(33060, Proto.TCP, "mysql")).module == "mysql"
    assert references.match(_svc(14330, Proto.TCP, "ms-sql-s")).module == "mssql"
    assert references.match(_svc(6380, Proto.TCP, "redis")).module == "redis"
    # the standard port still wins by specificity (port match > service-name fallback)
    assert references.match(_svc(3306, Proto.TCP, "mysql")).label == "MySQL"


def test_multiple_http_instances_each_route_independently() -> None:
    a = references.match(_svc(8080, Proto.TCP, "http-alt"))
    b = references.match(_svc(8000, Proto.TCP, "http"))
    assert a.module == "http" and b.module == "http"
    assert a.label != b.label  # distinct per-port labels, not a merged node


def test_service_name_fallback_urls_are_live_fetchable() -> None:
    # every mapped URL (incl. the new fallbacks) must satisfy the live-fetch allow-list
    from oscprecon.references import live_hacktricks

    for svc in (_svc(33060, Proto.TCP, "mysql"), _svc(2222, Proto.TCP, "ssh")):
        ref = references.match(svc)
        assert ref is not None and live_hacktricks.is_fetchable(ref.hacktricks)


def test_edb_persistence_never_stores_the_poc_path(tmp_path: Path) -> None:
    from oscprecon import edb

    hit = references.ExploitHit(
        edb_id="12345",
        title="Example",
        url="https://www.exploit-db.com/exploits/12345",
        path="/usr/share/exploitdb/exploits/linux/remote/12345.py",
    )
    edb.add_edb(tmp_path, service="ssh:22", product="OpenSSH", version="8.4", hits=[hit])
    stored = (tmp_path / "edb.json").read_text(encoding="utf-8")
    assert "12345" in stored and "exploit-db.com" in stored  # the reference is recorded
    assert "12345.py" not in stored and "/exploitdb/" not in stored  # but NEVER the PoC path


def test_expand_hint() -> None:
    out = references.expand_hint("smbclient //{target}/{share} -N", target="10.10.10.5", share="IT")
    assert out == "smbclient //10.10.10.5/IT -N"
    assert references.expand_hint("whatweb http://{target}:{port}", target="x", port=8080) == (
        "whatweb http://x:8080"
    )


def test_parse_searchsploit_json() -> None:
    text = (FIXTURES / "searchsploit" / "nginx.json").read_text(encoding="utf-8")
    hits = references.parse_searchsploit_json(text)
    assert len(hits) == 2
    first = hits[0]
    assert first.edb_id == "50973"
    assert first.url == "https://www.exploit-db.com/exploits/50973"
    assert "nginx" in first.title.lower()


def test_parse_searchsploit_handles_garbage() -> None:
    assert references.parse_searchsploit_json("not json") == []
    assert references.parse_searchsploit_json("{}") == []


def test_safe_query_strips_shell_hostile_chars() -> None:
    # nmap banners with quotes/parens must not reach the command line raw
    assert references._safe_query("OpenSSH", "8.4p1 Debian (protocol 2.0)") == (
        "OpenSSH 8.4p1 Debian protocol 2.0"
    )
    assert references._safe_query("", "") == ""


def test_safe_query_strips_leading_dash_flags() -> None:
    # a hostile nmap banner must not inject searchsploit flags via a leading dash
    assert references._safe_query("-m", "47080") == "m 47080"
    assert references._safe_query("Apache", "-u") == "Apache u"
    assert not any(tok.startswith("-") for tok in references._safe_query("--json", "x").split())


def test_match_tiebreak_prefers_specific_product() -> None:
    svc = _svc(18080, Proto.TCP, "http", "Apache Tomcat", "9.0.30")
    ref = references.match(svc)
    assert ref is not None
    assert ref.label == "Apache Tomcat"  # not the generic "Apache httpd"


def test_load_rules_degrades_on_malformed_yaml(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("key: [unterminated\n:::\n", encoding="utf-8")
    assert references.load_rules(bad) == []
    nonlist = tmp_path / "nl.yaml"
    nonlist.write_text("just a string", encoding="utf-8")
    assert references.load_rules(nonlist) == []
