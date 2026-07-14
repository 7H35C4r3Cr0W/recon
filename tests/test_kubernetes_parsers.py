from oscprecon.modules.kubernetes import (
    parse_kube_api,
    parse_kube_healthz,
    parse_kube_tool,
    parse_kube_version,
)

_VERSION = '{"major":"1","minor":"21","gitVersion":"v1.21.1","platform":"linux/amd64"}'
_API_ANON = '{"kind":"APIVersions","versions":["v1"],"serverAddressByClientCIDRs":[]}'
_API_FORBIDDEN = (
    '{"kind":"Status","apiVersion":"v1","status":"Failure",'
    '"message":"forbidden: User \\"system:anonymous\\" cannot get path \\"/api\\"",'
    '"reason":"Forbidden","code":403}'
)


def test_version_reads_gitversion() -> None:
    values = {f.kind: f.value for f in parse_kube_version(_VERSION)}
    assert values["version"] == "v1.21.1"


def test_api_anonymous_access_flagged() -> None:
    findings = parse_kube_api(_API_ANON)
    assert findings and findings[0].kind == "access" and findings[0].value == "anonymous"


def test_api_forbidden_flagged() -> None:
    findings = parse_kube_api(_API_FORBIDDEN)
    assert findings and findings[0].value == "forbidden"


def test_healthz_ok() -> None:
    findings = parse_kube_healthz("ok")
    assert findings and findings[0].value == "ok"


def test_missing_sentinel_skipped() -> None:
    assert parse_kube_version("[missing] curl — install with: apt install curl\n") == []


def test_tool_dispatch_unknown_returns_empty() -> None:
    assert parse_kube_tool("nope", _VERSION) == []
    assert parse_kube_tool("k8s-version", _VERSION)
