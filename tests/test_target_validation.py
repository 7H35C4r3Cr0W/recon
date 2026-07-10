import pytest

from oscprecon.models import Target, validate_host


def test_accepts_ipv4_ipv6_and_hostname() -> None:
    assert Target(ip="10.10.10.100").ip == "10.10.10.100"
    assert Target(ip="::1").ip == "::1"
    assert Target(ip="active.htb", hostname="dc01.active.htb").hostname == "dc01.active.htb"
    assert validate_host("127.0.0.1") == "127.0.0.1"


@pytest.mark.parametrize(
    "bad",
    [
        "10.10.10.5 --script ssh-brute",
        "-oX /tmp/x",
        "a b",
        "",
        "10.10.10.5;whoami",
        "$(id)",
    ],
)
def test_rejects_injection_and_junk(bad: str) -> None:
    with pytest.raises(ValueError):
        Target(ip=bad)


def test_rejects_bad_hostname_field() -> None:
    with pytest.raises(ValueError):
        Target(ip="10.10.10.5", hostname="evil host")
