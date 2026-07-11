from pathlib import Path

from oscprecon.modules.smtp.parsers import parse_nmap_smtp, parse_smtp_tool

FIX = Path(__file__).parent / "fixtures" / "smtp"


def _read(name: str) -> str:
    return (FIX / name).read_text(encoding="utf-8")


def test_parse_banner() -> None:
    findings = parse_nmap_smtp(_read("nmap-smtp.txt"))
    banners = [f.value for f in findings if f.kind == "banner"]
    assert banners == ["Postfix smtpd"]


def test_parse_verbs() -> None:
    verbs = {f.value for f in parse_nmap_smtp(_read("nmap-smtp.txt")) if f.kind == "verb"}
    assert {"VRFY", "EXPN", "ETRN", "STARTTLS", "AUTH"} <= verbs
    # a hostname token that merely contains a verb substring must not register as a verb
    assert "TURN" not in verbs  # ETRN present, TURN is not


def test_verb_not_matched_inside_hostname() -> None:
    text = "25/tcp open smtp\n| smtp-commands: vrfy-server.example.com Hello, SIZE 100, HELP\n"
    verbs = {f.value for f in parse_nmap_smtp(text) if f.kind == "verb"}
    assert "VRFY" not in verbs  # 'vrfy-server.example.com' is one token, not the VRFY verb


def test_parse_open_relay_allowed() -> None:
    findings = parse_nmap_smtp(_read("nmap-smtp.txt"))
    relay = [f for f in findings if f.kind == "open-relay"]
    assert relay and relay[0].value == "allowed"


def test_parse_open_relay_denied() -> None:
    text = (
        "25/tcp open smtp\n"
        "|_smtp-open-relay: Server doesn't seem to be an open relay, all tests failed\n"
    )
    relay = [f for f in parse_nmap_smtp(text) if f.kind == "open-relay"]
    assert relay and relay[0].value == "denied"


def test_parse_ntlm_info() -> None:
    ntlm = {f.value for f in parse_nmap_smtp(_read("nmap-smtp.txt")) if f.kind == "ntlm"}
    assert "DNS_Domain_Name: example.htb" in ntlm
    assert "DNS_Computer_Name: mail01.example.htb" in ntlm
    assert "NetBIOS_Domain_Name: EXAMPLE" in ntlm


def test_dispatch_and_garbage() -> None:
    assert parse_smtp_tool("unknown", "x") == []
    assert parse_smtp_tool("nmap-smtp", _read("nmap-smtp.txt"))
    assert parse_nmap_smtp("total 8\nnot an nmap line") == []
