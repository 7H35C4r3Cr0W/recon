from oscprecon.modules.svn import SvnModule, parse_svn_ls, parse_svn_nmap, parse_svn_tool

_LS = """branches/
tags/
trunk/
readme.txt
"""

_LS_DENIED = "svn: E170001: Authorization failed\n"

_NMAP = """3690/tcp open svnserve Subversion 1.14
| svn-info:
|   Repository UUID: 1b9c3a1e-0000-0000-0000-abcdef012345
|_  Last changed rev: 42
"""


def test_ls_flags_anonymous_and_lists_entries() -> None:
    values = {(f.kind, f.value) for f in parse_svn_ls(_LS)}
    assert ("access", "anonymous") in values
    assert ("entry", "trunk/") in values
    assert ("entry", "readme.txt") in values


def test_ls_auth_denied_yields_empty() -> None:
    assert parse_svn_ls(_LS_DENIED) == []


def test_nmap_parses_version_uuid_revision() -> None:
    values = {f.kind: f.value for f in parse_svn_nmap(_NMAP)}
    assert "Subversion 1.14" in values["version"]
    assert values["uuid"].startswith("1b9c3a1e")
    assert values["revision"] == "42"


def test_module_dedupes_across_steps() -> None:
    module = SvnModule()
    found = module.parse({"svn-ls": _LS, "svn-nmap": _NMAP})
    kinds = {f.fields["kind"] for f in found}
    assert {"access", "entry", "version", "uuid", "revision"} <= kinds


def test_missing_sentinel_skipped() -> None:
    assert parse_svn_ls("[missing] svn — install with: apt install subversion\n") == []


def test_tool_dispatch_unknown_returns_empty() -> None:
    assert parse_svn_tool("nope", _LS) == []
    assert parse_svn_tool("svn-ls", _LS)
