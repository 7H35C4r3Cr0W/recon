from oscprecon.modules.couchdb import (
    parse_couch_dbs,
    parse_couch_membership,
    parse_couch_root,
    parse_couch_tool,
)

_ROOT = '{"couchdb":"Welcome","version":"3.1.1","vendor":{"name":"The Apache Software Foundation"}}'
_DBS = '["_replicator","_users","secrets"]'
_MEMBERSHIP = '{"all_nodes":["couchdb@127.0.0.1"],"cluster_nodes":["couchdb@127.0.0.1"]}'
_AUTH = '{"error":"unauthorized","reason":"You are not authorized to access this db."}'


def test_root_extracts_version() -> None:
    values = {f.kind: f.value for f in parse_couch_root(_ROOT)}
    assert values["version"] == "3.1.1"


def test_root_auth_required_flagged() -> None:
    findings = parse_couch_root(_AUTH)
    assert len(findings) == 1 and findings[0].value == "auth-required"


def test_all_dbs_flags_unauth_and_lists_databases() -> None:
    values = {(f.kind, f.value) for f in parse_couch_dbs(_DBS)}
    assert ("access", "unauth") in values
    assert ("database", "secrets") in values


def test_all_dbs_empty_on_auth_error() -> None:
    assert parse_couch_dbs(_AUTH) == []


def test_membership_lists_nodes() -> None:
    nodes = {f.value for f in parse_couch_membership(_MEMBERSHIP) if f.kind == "node"}
    assert "couchdb@127.0.0.1" in nodes


def test_missing_sentinel_skipped() -> None:
    assert parse_couch_root("[missing] curl — install with: apt install curl\n") == []


def test_tool_dispatch_unknown_returns_empty() -> None:
    assert parse_couch_tool("nope", _ROOT) == []
    assert parse_couch_tool("couch-root", _ROOT)
