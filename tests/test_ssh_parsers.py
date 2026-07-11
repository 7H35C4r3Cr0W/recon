from pathlib import Path

from oscprecon.modules.ssh.parsers import parse_nmap_ssh, parse_ssh_tool

FIX = Path(__file__).parent / "fixtures" / "ssh"


def _read(name: str) -> str:
    return (FIX / name).read_text(encoding="utf-8")


def test_parse_banner() -> None:
    findings = parse_nmap_ssh(_read("nmap-ssh.txt"))
    banners = [f.value for f in findings if f.kind == "banner"]
    assert banners == ["OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)"]


def test_parse_host_keys() -> None:
    findings = parse_nmap_ssh(_read("nmap-ssh.txt"))
    keys = {f.value for f in findings if f.kind == "hostkey"}
    assert "RSA 2048" in keys
    assert "ECDSA 256" in keys
    assert "ED25519 256" in keys
    rsa = next(f for f in findings if f.kind == "hostkey" and f.value == "RSA 2048")
    assert "aa:bb:cc" in rsa.detail  # fingerprint kept in detail


def test_parse_weak_algorithms() -> None:
    weak = {f.value for f in parse_nmap_ssh(_read("nmap-ssh.txt")) if f.kind == "algo-weak"}
    assert "aes256-cbc" in weak
    assert "3des-cbc" in weak
    assert "diffie-hellman-group1-sha1" in weak
    assert "hmac-md5" in weak
    # modern algos and non-algo tokens must NOT be flagged
    assert "aes128-ctr" not in weak
    assert "chacha20-poly1305@openssh.com" not in weak
    assert "none" not in weak
    assert "password" not in weak
    assert "diffie-hellman-group14-sha1" not in weak  # group14 is not in the weak set


def test_parse_auth_methods() -> None:
    findings = parse_nmap_ssh(_read("nmap-ssh.txt"))
    methods = {f.value for f in findings if f.kind == "auth"}
    assert methods == {"publickey", "password"}
    password = next(f for f in findings if f.kind == "auth" and f.value == "password")
    assert "password authentication enabled" in password.detail


def test_auth_block_does_not_bleed_into_service_info() -> None:
    # the line after the methods ("Service Info: ...") must not be captured as an auth method
    findings = parse_nmap_ssh(_read("nmap-ssh.txt"))
    values = {f.value for f in findings if f.kind == "auth"}
    assert not any("Service Info" in v for v in values)
    assert "keyboard-interactive" not in values  # not offered by this host


def test_password_only_when_offered() -> None:
    denied = (
        "22/tcp open  ssh     OpenSSH 8.4p1 Debian\n"
        "| ssh-auth-methods:\n"
        "|   Supported authentication methods:\n"
        "|_    publickey\n"
    )
    findings = parse_nmap_ssh(denied)
    methods = {f.value for f in findings if f.kind == "auth"}
    assert methods == {"publickey"}
    assert not any(f.kind == "auth" and f.value == "password" for f in findings)


def test_dispatch_and_garbage() -> None:
    assert parse_ssh_tool("unknown", "x") == []
    assert parse_ssh_tool("nmap-ssh", _read("nmap-ssh.txt"))
    assert parse_nmap_ssh("total 8\nnot an nmap line") == []
