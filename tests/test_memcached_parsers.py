from pathlib import Path

from oscprecon.modules.memcached import parse_memcached_info, parse_memcached_tool

_FIX = Path(__file__).parent / "fixtures" / "memcached" / "nmap-info.txt"


def _info() -> str:
    return _FIX.read_text(encoding="utf-8")


def test_parses_access_version_items_conns() -> None:
    values = {f.kind: f.value for f in parse_memcached_info(_info())}
    assert values["access"] == "unauth"
    assert values["version"] == "1.6.9"
    assert values["items"] == "42"
    assert values["connections"] == "5"


def test_bare_sv_without_stats_yields_empty() -> None:
    # no stats block (no version/pid line) -> do not claim unauth access
    assert parse_memcached_info("11211/tcp open memcached\n") == []


def test_missing_sentinel_skipped() -> None:
    assert parse_memcached_info("[missing] nmap — install with: apt install nmap\n") == []


def test_tool_dispatch_unknown_returns_empty() -> None:
    assert parse_memcached_tool("nope", _info()) == []
    assert parse_memcached_tool("memcached-info", _info())
