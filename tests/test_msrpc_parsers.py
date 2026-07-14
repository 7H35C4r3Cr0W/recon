from oscprecon.modules.msrpc import MsrpcModule, parse_msrpc_tool, parse_rpcdump

_RPCDUMP = """Protocol: [MS-RPCE]: Remote Management Interface
Provider: rpcrt4.dll
UUID    : afa8bd80-7d8a-11c9-bef4-08002b102989 v1.0
Bindings:
          ncacn_ip_tcp:10.10.10.5[49664]
          ncacn_np:\\\\HOST[\\pipe\\atsvc]

Protocol: N/A
UUID    : 12345678-1234-abcd-ef00-0123456789ab v1.0
Bindings:
          ncacn_np:\\\\HOST[\\pipe\\lsass]
"""


def test_rpcdump_counts_endpoints_and_pipes() -> None:
    values = {(f.kind, f.value) for f in parse_rpcdump(_RPCDUMP)}
    assert ("access", "unauth") in values
    assert ("endpoints", "2") in values
    assert ("pipe", "atsvc") in values
    assert ("pipe", "lsass") in values


def test_rpcdump_empty_when_no_uuid_or_pipe() -> None:
    assert parse_rpcdump("135/tcp open msrpc\n") == []


def test_module_dedupes_pipes_across_steps() -> None:
    module = MsrpcModule()
    nmap = "135/tcp open msrpc Microsoft Windows RPC\n| msrpc-enum:\n|_  \\pipe\\atsvc\n"
    found = module.parse({"msrpc-rpcdump": _RPCDUMP, "msrpc-nmap": nmap})
    pipes = [f.fields["value"] for f in found if f.fields["kind"] == "pipe"]
    assert pipes.count("atsvc") == 1  # atsvc from both steps collapses to one


def test_missing_sentinel_skipped() -> None:
    assert parse_rpcdump("[missing] impacket-rpcdump — install with: apt install impacket\n") == []


def test_tool_dispatch_unknown_returns_empty() -> None:
    assert parse_msrpc_tool("nope", _RPCDUMP) == []
    assert parse_msrpc_tool("msrpc-rpcdump", _RPCDUMP)
