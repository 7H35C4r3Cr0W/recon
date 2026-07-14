from oscprecon.modules.rmi import RmiModule, parse_rmi_info, parse_rmi_tool

_NMAP = """1099/tcp open java-rmi Java RMI
| rmi-dumpregistry:
|   jmxrmi
|     implements javax.management.remote.rmi.RMIServerImpl_Stub
|     extends java.rmi.server.RemoteStub
|     @10.10.10.37:37655
|_  registry
"""


def test_parses_bound_objects() -> None:
    objects = {f.value for f in parse_rmi_info(_NMAP) if f.kind == "object"}
    assert "jmxrmi" in objects
    assert "registry" in objects


def test_class_and_impl_lines_not_treated_as_objects() -> None:
    objects = {f.value for f in parse_rmi_info(_NMAP) if f.kind == "object"}
    assert not any("javax" in o or "." in o for o in objects)  # class paths excluded


def test_parses_dynamic_endpoint() -> None:
    endpoints = {f.value for f in parse_rmi_info(_NMAP) if f.kind == "endpoint"}
    assert "10.10.10.37:37655" in endpoints


def test_parses_version() -> None:
    values = {f.kind: f.value for f in parse_rmi_info(_NMAP)}
    assert "Java RMI" in values["version"]


def test_jmxrmi_drives_jmx_suggestion() -> None:
    tips = RmiModule().suggest(parse_rmi_info_as_findings())
    assert tips and "jmx" in tips[0].lower()


def parse_rmi_info_as_findings() -> list:
    return RmiModule().parse({"rmi-info": _NMAP})


def test_missing_sentinel_skipped() -> None:
    assert parse_rmi_info("[missing] nmap — install with: apt install nmap\n") == []


def test_tool_dispatch_unknown_returns_empty() -> None:
    assert parse_rmi_tool("nope", _NMAP) == []
    assert parse_rmi_tool("rmi-info", _NMAP)
