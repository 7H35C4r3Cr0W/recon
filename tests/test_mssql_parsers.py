from pathlib import Path

from oscprecon.modules.mssql import parse_mssql_info

_FIXDIR = Path(__file__).parent / "fixtures" / "mssql"
_FIX = _FIXDIR / "nmap-info.txt"


def _info() -> str:
    return _FIX.read_text(encoding="utf-8")


def _read(name: str) -> str:
    return (_FIXDIR / name).read_text(encoding="utf-8")


def test_parses_version_instance_host() -> None:
    kinds = {(f.kind, f.value) for f in parse_mssql_info(_info())}
    assert ("instance", "MSSQLSERVER") in kinds
    assert ("hostname", "SQL-01") in kinds
    assert any(k == "version" and "Microsoft SQL Server 2019" in v for k, v in kinds)


def test_parses_ad_domain_and_os_build() -> None:
    values = {f.kind: f.value for f in parse_mssql_info(_info())}
    assert values.get("domain") == "corp.local"
    assert values.get("os-build") == "10.0.17763"


def test_standalone_domain_equal_host_is_skipped() -> None:
    text = (
        "Windows server name: WIN-01\nNetBIOS_Computer_Name: WIN-01\nNetBIOS_Domain_Name: WIN-01\n"
    )
    kinds = {f.kind for f in parse_mssql_info(text)}
    assert "hostname" in kinds
    assert "domain" not in kinds  # domain == host -> standalone box, not an AD domain


def test_missing_sentinel_skipped() -> None:
    assert parse_mssql_info("[missing] nmap — install with: apt install nmap\n") == []


def test_sv_only_version_fallback() -> None:
    # ms-sql-info/ntlm-info blocked — only the -sV service line remains; version must still parse.
    kinds = {(f.kind, f.value) for f in parse_mssql_info(_read("nmap-sv-only.txt"))}
    assert any(k == "version" and "Microsoft SQL Server 2019" in v for k, v in kinds)
    assert not any(k == "instance" for k, _ in kinds)  # no ms-sql-info block -> no instance


def test_bare_service_line_does_not_bleed_into_version() -> None:
    # a bare `ms-sql-s` service line must NOT capture the following ntlm-info header as a version.
    text = "1433/tcp open  ms-sql-s\n| ms-sql-ntlm-info:\n|   Target_Name: SQLBOX\n"
    assert not any(f.kind == "version" for f in parse_mssql_info(text))


def test_multi_instance_all_parsed() -> None:
    findings = parse_mssql_info(_read("nmap-multi-instance.txt"))
    instances = {f.value for f in findings if f.kind == "instance"}
    versions = {f.value for f in findings if f.kind == "version"}
    assert instances == {"MSSQLSERVER", "SQLEXPRESS"}
    assert any("Microsoft SQL Server 2019" in v for v in versions)
    assert any("Microsoft SQL Server 2014" in v for v in versions)  # 2nd instance not dropped


def test_workgroup_not_labeled_ad_domain() -> None:
    # a standalone host reports NetBIOS_Domain_Name: WORKGROUP — that is not an AD domain.
    text = "NetBIOS_Computer_Name: SQLBOX\nNetBIOS_Domain_Name: WORKGROUP\n"
    kinds = {f.kind for f in parse_mssql_info(text)}
    assert "hostname" in kinds
    assert "domain" not in kinds
