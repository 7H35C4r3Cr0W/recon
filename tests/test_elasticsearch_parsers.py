from oscprecon.modules.elasticsearch import (
    parse_elastic_health,
    parse_elastic_indices,
    parse_elastic_root,
    parse_elastic_tool,
)

_ROOT = """{
  "name" : "node-1",
  "cluster_name" : "es-prod",
  "version" : { "number" : "7.10.0", "lucene_version" : "8.7.0" },
  "tagline" : "You Know, for Search"
}"""

_INDICES = """health status index         uuid   pri rep docs.count docs.deleted store.size
green  open   bank           abc      1   0       1000            0      400kb
yellow open   .kibana_1      def      1   1          1            0        5kb
"""

_HEALTH = '{"cluster_name":"es-prod","status":"green","number_of_nodes":3}'

_AUTH = '{"error":{"type":"security_exception","reason":"missing auth"},"status":401}'


def test_root_unauth_extracts_version_and_cluster() -> None:
    values = {(f.kind, f.value) for f in parse_elastic_root(_ROOT)}
    assert ("access", "unauth") in values
    assert ("version", "7.10.0") in values
    assert ("cluster", "es-prod") in values


def test_root_auth_required_flagged() -> None:
    findings = parse_elastic_root(_AUTH)
    assert len(findings) == 1 and findings[0].value == "auth-required"


def test_indices_parsed_skipping_header() -> None:
    names = {f.value for f in parse_elastic_indices(_INDICES)}
    assert names == {"bank", ".kibana_1"}


def test_indices_empty_when_auth_error() -> None:
    assert parse_elastic_indices(_AUTH) == []


def test_health_status_and_nodes() -> None:
    values = {f.kind: f.value for f in parse_elastic_health(_HEALTH)}
    assert values["status"] == "green"
    assert values["nodes"] == "3"


def test_missing_sentinel_skipped() -> None:
    assert parse_elastic_root("[missing] curl — install with: apt install curl\n") == []


def test_tool_dispatch_unknown_returns_empty() -> None:
    assert parse_elastic_tool("nope", _ROOT) == []
    assert parse_elastic_tool("es-root", _ROOT)
