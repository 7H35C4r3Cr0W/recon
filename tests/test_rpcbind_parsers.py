from oscprecon.modules.rpcbind import RpcbindModule, parse_rpcbind_tool, parse_rpcinfo

_RPCINFO = """   program vers proto   port  service
    100000    4   tcp    111  portmapper
    100000    3   udp    111  portmapper
    100003    3   tcp   2049  nfs
    100005    1   udp  20048  mountd
    100024    1   tcp  35678  status
"""

_NMAP = """111/tcp open rpcbind
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|_  100003  3           2049/tcp   nfs
"""


def test_rpcinfo_parses_programs_and_flags_unauth() -> None:
    values = {(f.kind, f.value) for f in parse_rpcinfo(_RPCINFO)}
    assert ("access", "unauth") in values
    assert ("program", "nfs") in values
    assert ("program", "mountd") in values
    assert ("program", "status") in values


def test_portmapper_deduped_within_output() -> None:
    programs = [f for f in parse_rpcinfo(_RPCINFO) if f.value == "portmapper"]
    assert len(programs) == 1  # two portmapper rows (tcp+udp) collapse to one finding


def test_header_row_not_treated_as_program() -> None:
    names = {f.value for f in parse_rpcinfo(_RPCINFO) if f.kind == "program"}
    assert "service" not in names  # the "program vers proto ..." header is skipped


def test_module_dedupes_across_rpcinfo_and_nmap() -> None:
    module = RpcbindModule()
    found = module.parse({"rpcbind-rpcinfo": _RPCINFO, "rpcbind-nmap": _NMAP})
    nfs = [f for f in found if f.fields["kind"] == "program" and f.fields["value"] == "nfs"]
    assert len(nfs) == 1  # nfs from both tools collapses


def test_suggest_flags_nfs() -> None:
    module = RpcbindModule()
    tips = module.suggest(module.parse({"rpcbind-rpcinfo": _RPCINFO}))
    assert any("showmount" in t for t in tips)


def test_missing_sentinel_skipped() -> None:
    assert parse_rpcinfo("[missing] rpcinfo — install with: apt install rpcbind\n") == []


def test_tool_dispatch_unknown_returns_empty() -> None:
    assert parse_rpcbind_tool("nope", _RPCINFO) == []
    assert parse_rpcbind_tool("rpcbind-rpcinfo", _RPCINFO)
