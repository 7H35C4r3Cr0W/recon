from oscprecon.modules.x11 import parse_x11_access, parse_x11_tool

_GRANTED = "6000/tcp open  X11\n| x11-access:\n|_  X server access is granted\n"
_DENIED = "6000/tcp open  X11 (access denied)\n| x11-access:\n|_  X server access is denied\n"


def test_granted_flags_anonymous_access() -> None:
    values = {f.kind: f.value for f in parse_x11_access(_GRANTED)}
    assert values["access"] == "anonymous"  # open display -> notable exposure


def test_denied_is_not_anonymous() -> None:
    values = {f.kind: f.value for f in parse_x11_access(_DENIED)}
    assert values["access"] == "denied"


def test_missing_sentinel_skipped() -> None:
    assert parse_x11_access("[missing] nmap — install with: apt install nmap\n") == []


def test_no_x11_lines_yields_empty() -> None:
    assert parse_x11_access("6000/tcp filtered X11\n") == []


def test_tool_dispatch_unknown_returns_empty() -> None:
    assert parse_x11_tool("nope", _GRANTED) == []
    assert parse_x11_tool("x11-access", _GRANTED)  # known key parses
