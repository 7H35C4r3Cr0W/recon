from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

# awscli writes a missing/blocked sentinel or its own connection/permission errors to the file — a
# recon operator must never mistake "the endpoint was unreachable" for "no buckets exist", so an
# error line becomes an explicit `error` finding rather than an empty result.
_SENTINEL = ("[missing]", "[blocked]")
_ERROR_RE = re.compile(
    r"(could not connect|error occurred|access denied|invalidaccesskeyid|nosuchbucket|"
    r"endpoint url|unable to locate credentials|\[error\])",
    re.IGNORECASE,
)

# `aws s3 ls`               -> "2021-08-13 09:52:29 thetoppers.htb"          (date time bucket)
# `aws s3 ls s3://bucket`   -> "2021-08-13 09:52:29     11952 index.php"     (date time size object)
#                             "                          PRE images/"        (a prefix / "folder")
_BUCKET_RE = re.compile(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\s+(?P<name>\S+)\s*$")
_OBJECT_RE = re.compile(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\s+(?P<size>\d+)\s+(?P<name>\S.*?)\s*$")
_PREFIX_RE = re.compile(r"^\s*PRE\s+(?P<name>\S.*?)\s*$")


@dataclass
class S3Finding:
    kind: str  # bucket | object | prefix | error
    value: str
    detail: str = ""
    module: str = "s3"

    def to_dict(self, discovered_at: str) -> dict[str, Any]:
        return {
            "module": self.module,
            "kind": self.kind,
            "value": self.value,
            "detail": self.detail,
            "discovered_at": discovered_at,
        }


def _errors(text: str) -> list[S3Finding]:
    return [
        S3Finding("error", line.strip(), "awscli reported an error — endpoint/creds, not empty")
        for line in text.splitlines()
        if _ERROR_RE.search(line)
    ]


def parse_s3_buckets(text: str) -> list[S3Finding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    findings = _errors(text)
    for line in text.splitlines():
        match = _BUCKET_RE.match(line)
        if match is not None:
            findings.append(S3Finding("bucket", match.group("name")))
    return findings


def parse_s3_objects(text: str) -> list[S3Finding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    findings = _errors(text)
    for line in text.splitlines():
        prefix = _PREFIX_RE.match(line)
        if prefix is not None:
            findings.append(S3Finding("prefix", prefix.group("name")))
            continue
        obj = _OBJECT_RE.match(line)
        if obj is not None:
            findings.append(S3Finding("object", obj.group("name"), f"{obj.group('size')} bytes"))
    return findings


_PARSERS = {"s3-buckets": parse_s3_buckets, "s3-objects": parse_s3_objects}


def parse_s3_tool(tool: str, text: str) -> list[S3Finding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
