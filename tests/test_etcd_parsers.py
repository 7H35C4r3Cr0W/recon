from oscprecon.modules.etcd import (
    parse_etcd_keys,
    parse_etcd_members,
    parse_etcd_tool,
    parse_etcd_version,
)

_VERSION = '{"etcdserver":"3.3.11","etcdcluster":"3.3.0"}'
_MEMBERS = '{"members":[{"id":"8e9e05","name":"etcd0","clientURLs":["http://10.0.0.1:2379"]}]}'
_KEYS = (
    '{"action":"get","node":{"key":"/","dir":true,"nodes":['
    '{"key":"/secrets","dir":true},{"key":"/config","value":"x"}]}}'
)
_V2_DISABLED = '{"errorCode":404,"message":"Not Found","cause":"/v2/keys"}'


def test_version_flags_unauth_and_reads_version() -> None:
    values = {(f.kind, f.value) for f in parse_etcd_version(_VERSION)}
    assert ("access", "unauth") in values
    assert ("version", "3.3.11") in values


def test_members_lists_names() -> None:
    names = {f.value for f in parse_etcd_members(_MEMBERS) if f.kind == "member"}
    assert "etcd0" in names


def test_keys_flags_unauth_and_lists_top_level_keys() -> None:
    values = {(f.kind, f.value) for f in parse_etcd_keys(_KEYS)}
    assert ("access", "unauth") in values
    assert ("key", "/secrets") in values
    assert ("key", "/config") in values


def test_keys_empty_when_v2_disabled() -> None:
    assert parse_etcd_keys(_V2_DISABLED) == []


def test_non_json_yields_empty() -> None:
    assert parse_etcd_version("curl: (7) Failed to connect\n") == []


def test_missing_sentinel_skipped() -> None:
    assert parse_etcd_version("[missing] curl — install with: apt install curl\n") == []


def test_tool_dispatch_unknown_returns_empty() -> None:
    assert parse_etcd_tool("nope", _VERSION) == []
    assert parse_etcd_tool("etcd-version", _VERSION)
