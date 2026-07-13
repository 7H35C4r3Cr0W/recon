from pathlib import Path

from oscprecon.modules.postgresql import parse_postgresql_info

_FIXDIR = Path(__file__).parent / "fixtures" / "postgresql"


def _read(name: str) -> str:
    return (_FIXDIR / name).read_text(encoding="utf-8")


def _kinds(text: str) -> set[tuple[str, str]]:
    return {(f.kind, f.value) for f in parse_postgresql_info(text)}


def test_normal_sv_output() -> None:
    kinds = _kinds(_read("nmap-sv.txt"))
    assert ("service", "PostgreSQL") in kinds
    assert ("version", "9.6.0 or later") in kinds
    assert ("port", "5432") in kinds  # port emitted for interpolation (detail flags standard)
    assert not any(k == "tls" for k, _ in kinds)
    # the standard port carries a "standard" detail; a non-standard one is flagged
    port = next(f for f in parse_postgresql_info(_read("nmap-sv.txt")) if f.kind == "port")
    assert "standard" in port.detail and "non-standard" not in port.detail


def test_tls_wrapped_output() -> None:
    kinds = _kinds(_read("nmap-sv-tls.txt"))
    assert ("service", "PostgreSQL") in kinds
    assert ("tls", "enabled") in kinds
    assert ("version", "13.4 - 13.7") in kinds


def test_non_standard_port_output() -> None:
    kinds = _kinds(_read("nmap-sv-nonstandard.txt"))
    assert ("service", "PostgreSQL") in kinds
    assert ("port", "5433") in kinds  # discovered off 5432
    assert ("version", "12.1") in kinds


def test_crlf_output() -> None:
    text = "PORT     STATE SERVICE    VERSION\r\n5432/tcp open  postgresql PostgreSQL DB 14.2\r\n"
    assert ("version", "14.2") in _kinds(text)


def test_bare_service_line_no_version() -> None:
    kinds = _kinds("5432/tcp open  postgresql\n")
    assert ("service", "PostgreSQL") in kinds
    assert not any(k == "version" for k, _ in kinds)  # no version text -> no version finding


def test_missing_sentinel_skipped() -> None:
    assert parse_postgresql_info("[missing] nmap — install with: apt install nmap\n") == []


def test_blocked_sentinel_skipped() -> None:
    assert parse_postgresql_info("[blocked] psql is not on the OSCP-allowed tool list\n") == []


def test_empty_input() -> None:
    assert parse_postgresql_info("") == []
    assert parse_postgresql_info("   \n\n") == []


def test_malformed_input_never_crashes() -> None:
    for junk in ("\x00\x01garbage", "5432/tcp", "open postgresql", "PostgreSQL\n\n5432"):
        assert isinstance(parse_postgresql_info(junk), list)


def test_unrelated_text_with_postgresql_is_not_a_finding() -> None:
    # a log/error line mentioning PostgreSQL must NOT be treated as service detection
    text = "psql: error: connection to server failed: FATAL: PostgreSQL is starting up\n"
    assert parse_postgresql_info(text) == []


def test_newline_bleed_next_section_not_captured() -> None:
    # a bare postgresql line followed by another nmap row must not bleed into the version
    text = "5432/tcp open  postgresql\n5984/tcp open  http CouchDB 3.2\n"
    assert not any(f.kind == "version" for f in parse_postgresql_info(text))


def test_no_duplicate_findings_on_repeat_parse() -> None:
    findings = parse_postgresql_info(_read("nmap-sv.txt"))
    keys = [(f.kind, f.value) for f in findings]
    assert len(keys) == len(set(keys))  # one finding per (kind, value)
