import shlex
from pathlib import Path

from oscprecon.models import Proto
from oscprecon.modules.s3 import (
    S3Module,
    is_s3_host,
    parse_s3_buckets,
    parse_s3_objects,
    parse_s3_tool,
    s3_recon_commands,
)
from oscprecon.shell import policy_violation

FIX = Path(__file__).parent / "fixtures" / "s3"


def test_is_s3_host() -> None:
    assert is_s3_host("s3.thetoppers.htb") and is_s3_host("bucket.s3.amazonaws.com")
    assert not is_s3_host("thetoppers.htb") and not is_s3_host("www.example.com")


def test_parse_buckets() -> None:
    text = "2021-08-13 09:52:29 thetoppers.htb\n2021-08-13 09:52:29 uploads\n"
    names = [f.value for f in parse_s3_buckets(text)]
    assert names == ["thetoppers.htb", "uploads"]


def test_parse_objects_and_prefixes() -> None:
    findings = parse_s3_objects((FIX / "objects.txt").read_text())
    by_kind = {(f.kind, f.value): f for f in findings}
    assert ("prefix", "images/") in by_kind  # a "folder"
    assert ("object", "index.php") in by_kind and ("object", ".htaccess") in by_kind
    assert by_kind[("object", "index.php")].detail == "11952 bytes"


def test_error_line_becomes_an_explicit_finding_not_empty() -> None:
    # the key error-handling guarantee: an unreachable endpoint must not read as "no buckets".
    text = 'aws: [ERROR]: Could not connect to the endpoint URL: "http://s3.x/"'
    findings = parse_s3_buckets(text)
    assert any(f.kind == "error" for f in findings)


def test_missing_tool_sentinel_is_skipped() -> None:
    assert parse_s3_buckets("[missing] aws — install with: apt install awscli") == []


def test_module_findings_are_s3_service() -> None:
    findings = S3Module().parse({"s3-buckets": "2021-08-13 09:52:29 thetoppers.htb"})
    assert findings and all(f.service == "s3" and f.proto == Proto.TCP for f in findings)


def test_recon_commands_are_read_only_and_policy_clean() -> None:
    commands = s3_recon_commands("s3.thetoppers.htb", bucket="thetoppers.htb")
    assert any("s3 ls" in c.shell_line and "s3://thetoppers.htb" in c.shell_line for c in commands)
    for command in commands:
        assert policy_violation(shlex.split(command.shell_line)) is None  # never blocked
        assert " cp " not in command.shell_line and " rm " not in command.shell_line


def test_parse_tool_dispatch() -> None:
    assert parse_s3_tool("unknown", "x") == []
    assert parse_s3_tool("s3-objects", "                           PRE data/")
