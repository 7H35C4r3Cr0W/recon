from pathlib import Path

from oscprecon.modules.mysql import parse_mysql_info

_FIXDIR = Path(__file__).parent / "fixtures" / "mysql"


def _read(name: str) -> str:
    return (_FIXDIR / name).read_text(encoding="utf-8")


def test_parses_version_protocol_auth_plugin() -> None:
    kinds = {(f.kind, f.value) for f in parse_mysql_info(_read("nmap-info.txt"))}
    assert ("version", "5.5.20-log") in kinds
    assert ("protocol", "10") in kinds
    assert ("auth-plugin", "mysql_native_password") in kinds


def test_sv_only_version_fallback() -> None:
    # mysql-info blocked — only the -sV service line remains; version must still parse.
    kinds = {(f.kind, f.value) for f in parse_mysql_info(_read("nmap-sv-only.txt"))}
    assert any(k == "version" and "MySQL 5.5.20-log" in v for k, v in kinds)
    assert not any(k == "protocol" for k, _ in kinds)  # no mysql-info table -> no protocol


def test_bare_service_line_does_not_bleed_into_version() -> None:
    # a bare `mysql` service line must NOT capture the following mysql-info row as a version.
    text = "3306/tcp open  mysql\n| mysql-info:\n|   Protocol: 10\n"
    kinds = {f.kind for f in parse_mysql_info(text)}
    assert "version" not in kinds
    assert "protocol" in kinds


def test_mariadb_service_line_captured() -> None:
    text = "PORT     STATE SERVICE VERSION\n3306/tcp open  mysql   MariaDB (unauthorized)\n"
    assert any(f.kind == "version" and "MariaDB" in f.value for f in parse_mysql_info(text))


def test_ssl_wrapped_service_line_captured() -> None:
    # nmap prints `ssl/mysql` for a TLS-wrapped banner — the fallback must still yield a version.
    text = "3306/tcp open  ssl/mysql MySQL 5.7.40\n"
    assert any(f.kind == "version" and "MySQL 5.7.40" in f.value for f in parse_mysql_info(text))


def test_auth_plugin_survives_crlf() -> None:
    text = (
        "3306/tcp open  mysql   MySQL 5.7.33\r\n| mysql-info:\r\n|   Protocol: 10\r\n"
        "|   Version: 5.7.33\r\n|_  Auth Plugin Name: caching_sha2_password\r\n"
    )
    kinds = {(f.kind, f.value) for f in parse_mysql_info(text)}
    assert ("auth-plugin", "caching_sha2_password") in kinds


def test_missing_sentinel_skipped() -> None:
    assert parse_mysql_info("[missing] nmap — install with: apt install nmap\n") == []
