from pathlib import Path

from oscprecon.modules.vhost.parsers import (
    parse_dnsrecon,
    parse_ffuf_vhost,
    parse_gobuster_vhost,
    parse_vhost_tool,
)

FIX = Path(__file__).parent / "fixtures" / "vhost"


def _read(name: str) -> str:
    return (FIX / name).read_text(encoding="utf-8")


def test_ffuf_vhost() -> None:
    findings = parse_ffuf_vhost(_read("ffuf-vhost.json"), "example.com")
    by_vhost = {f.vhost: f for f in findings}
    assert by_vhost["admin.example.com"].status == 200
    assert by_vhost["admin.example.com"].size == 1234
    assert by_vhost["dev.example.com"].status == 403


def test_gobuster_vhost() -> None:
    findings = parse_gobuster_vhost(_read("gobuster-vhost.txt"))
    by_vhost = {f.vhost: f for f in findings}
    assert by_vhost["admin.example.com"].status == 200
    assert by_vhost["admin.example.com"].size == 1234
    assert by_vhost["dev.example.com"].status == 403


def test_dnsrecon() -> None:
    findings = parse_dnsrecon(_read("dnsrecon.txt"))
    by_vhost = {f.vhost: f for f in findings}
    assert by_vhost["admin.example.com"].ip == "10.10.10.5"
    assert by_vhost["dev.example.com"].ip == "10.10.10.6"
    assert "www.example.com" in by_vhost


def test_dispatch_and_garbage() -> None:
    assert parse_vhost_tool("unknown", "x") == []
    assert parse_ffuf_vhost("not json", "d") == []
    assert parse_vhost_tool("ffuf", _read("ffuf-vhost.json"), "example.com")
    assert parse_vhost_tool("dnsrecon", _read("dnsrecon.txt"))
