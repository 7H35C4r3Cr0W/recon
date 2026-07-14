from oscprecon.modules.iscsi import IscsiModule, parse_iscsi_targets, parse_iscsi_tool

_DISCOVERY = """10.10.10.29:3260,1 iqn.2004-04.com.example:storage.disk1
10.10.10.29:3260,1 iqn.2004-04.com.example:storage.backup
"""

_NMAP = """3260/tcp open iscsi
| iscsi-info:
|   iqn.2004-04.com.example:storage.disk1
|_    Address: 10.10.10.29:3260,1
"""


def test_discovery_parses_targets_and_access() -> None:
    values = {(f.kind, f.value) for f in parse_iscsi_targets(_DISCOVERY)}
    assert ("access", "discovery-open") in values
    assert ("target", "iqn.2004-04.com.example:storage.disk1") in values
    assert ("target", "iqn.2004-04.com.example:storage.backup") in values


def test_no_iqn_yields_empty() -> None:
    assert parse_iscsi_targets("iscsiadm: No portals found\n") == []


def test_module_dedupes_targets_across_steps() -> None:
    module = IscsiModule()
    found = module.parse({"iscsi-discovery": _DISCOVERY, "iscsi-nmap": _NMAP})
    targets = [f.fields["value"] for f in found if f.fields["kind"] == "target"]
    assert targets.count("iqn.2004-04.com.example:storage.disk1") == 1  # shared target collapses


def test_missing_sentinel_skipped() -> None:
    assert parse_iscsi_targets("[missing] iscsiadm — install with: apt install open-iscsi\n") == []


def test_tool_dispatch_unknown_returns_empty() -> None:
    assert parse_iscsi_tool("nope", _DISCOVERY) == []
    assert parse_iscsi_tool("iscsi-discovery", _DISCOVERY)
