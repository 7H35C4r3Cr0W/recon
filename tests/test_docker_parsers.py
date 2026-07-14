from oscprecon.modules.docker import (
    parse_docker_containers,
    parse_docker_info,
    parse_docker_tool,
    parse_docker_version,
)

_VERSION = '{"Version":"20.10.7","ApiVersion":"1.41","Os":"linux","Arch":"amd64"}'
_INFO = '{"Containers":3,"Images":10,"Name":"docker-host","OperatingSystem":"Ubuntu 20.04"}'
_CONTAINERS = (
    '[{"Id":"abc123def456","Names":["/web"],"Image":"nginx:latest"},'
    '{"Id":"beef","Names":["/db"],"Image":"mysql"}]'
)


def test_version_flags_unauth_and_reads_version() -> None:
    values = {(f.kind, f.value) for f in parse_docker_version(_VERSION)}
    assert ("access", "unauth") in values
    assert ("version", "20.10.7") in values
    assert ("api", "1.41") in values


def test_info_counts_and_os() -> None:
    values = {f.kind: f.value for f in parse_docker_info(_INFO)}
    assert values["containers"] == "3"
    assert values["images"] == "10"
    assert values["os"] == "Ubuntu 20.04"


def test_containers_lists_names_and_images() -> None:
    names = {f.value for f in parse_docker_containers(_CONTAINERS)}
    assert "web (nginx:latest)" in names
    assert "db (mysql)" in names


def test_non_json_yields_empty() -> None:
    assert parse_docker_version("curl: (7) Failed to connect\n") == []


def test_missing_sentinel_skipped() -> None:
    assert parse_docker_version("[missing] curl — install with: apt install curl\n") == []


def test_tool_dispatch_unknown_returns_empty() -> None:
    assert parse_docker_tool("nope", _VERSION) == []
    assert parse_docker_tool("docker-version", _VERSION)
