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


def test_no_match_returns_none() -> None:
    assert references.match(_svc(1, Proto.TCP, "tcpwrapped")) is None


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
