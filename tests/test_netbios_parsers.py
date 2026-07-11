from pathlib import Path

from oscprecon.modules.netbios.parsers import (
    parse_nbtscan,
    parse_netbios_tool,
    parse_nmblookup,
)

FIX = Path(__file__).parent / "fixtures" / "netbios"


def _read(name: str) -> str:
    return (FIX / name).read_text(encoding="utf-8")


def test_nmblookup_hostname_domain_roles() -> None:
    findings = parse_nmblookup(_read("nmblookup-A.txt"))
    by_kind: dict[str, set[str]] = {}
    for f in findings:
        by_kind.setdefault(f.kind, set()).add(f.value)
    assert by_kind.get("hostname") == {"SRV01"}
    assert "MYDOMAIN" in by_kind.get("domain", set())
    roles = by_kind.get("role", set())
    assert "file-server (SMB)" in roles  # <20>
    assert "domain-controllers" in roles  # <1c>
    assert by_kind.get("mac") == {"00-50-56-AA-BB-CC"}


def test_nmblookup_user_and_msbrowse() -> None:
    findings = parse_nmblookup(_read("nmblookup-A.txt"))
    users = {f.value for f in findings if f.kind == "user"}
    assert users == {"ADMINPC"}  # <03> name, distinct from the hostname
    # __MSBROWSE__ is a browser artifact, never surfaced as a hostname/name
    assert "__MSBROWSE__" not in {f.value for f in findings}


def test_nmblookup_03_matching_hostname_is_not_a_user() -> None:
    # when the <03> name equals the host's own <00> name it is the computer, not a logged-in user
    text = (
        "\tSRV01           <00> -         M <ACTIVE>\n\tSRV01           <03> -         M <ACTIVE>\n"
    )
    assert not any(f.kind == "user" for f in parse_nmblookup(text))


def test_nmblookup_03_before_00_still_suppressed() -> None:
    # RFC 1002 node-status ordering is target-controlled; a <03> row that precedes its own <00> host
    # row must still be read as the computer name, not a logged-in user (order-independent two-pass)
    text = (
        "\tWKSTN           <03> -         B <ACTIVE>\n\tWKSTN           <00> -         B <ACTIVE>\n"
    )
    findings = parse_nmblookup(text)
    assert not any(f.kind == "user" for f in findings)
    assert any(f.kind == "hostname" and f.value == "WKSTN" for f in findings)


def test_nbtscan_name_server_mac() -> None:
    findings = parse_nbtscan(_read("nbtscan.txt"))
    assert any(f.kind == "hostname" and f.value == "SRV01" for f in findings)
    assert any(f.kind == "role" and "file-server" in f.value for f in findings)
    assert any(f.kind == "mac" and f.value == "00:50:56:aa:bb:cc" for f in findings)
    # the header/separator lines must not become findings
    assert not any(f.value.startswith("-") for f in findings)


def test_dispatch_and_garbage() -> None:
    assert parse_netbios_tool("unknown", "x") == []
    assert parse_netbios_tool("nmblookup", _read("nmblookup-A.txt"))
    assert parse_netbios_tool("nbtscan", _read("nbtscan.txt"))
    assert parse_nmblookup("Looking up status of 10.0.0.1\nNo reply\n") == []
    assert parse_nbtscan("IP address  NetBIOS Name\n---\n") == []
