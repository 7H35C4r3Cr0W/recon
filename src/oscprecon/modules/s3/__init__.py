from __future__ import annotations

from oscprecon.models import Command, Finding, Port, Proto, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.s3.parsers import (
    S3Finding,
    parse_s3_buckets,
    parse_s3_objects,
    parse_s3_tool,
)

__all__ = [
    "S3Finding",
    "S3Module",
    "is_s3_host",
    "parse_s3_buckets",
    "parse_s3_objects",
    "parse_s3_tool",
    "s3_recon_commands",
]


def is_s3_host(hostname: str) -> bool:
    # a vhost named s3.* (or *.s3.*) is the conventional S3 endpoint (Three: s3.thetoppers.htb).
    label = hostname.strip().lower()
    return label.startswith("s3.") or ".s3." in label


def s3_recon_commands(endpoint_host: str, bucket: str = "") -> list[Command]:
    # READ-ONLY S3 enumeration only (shell._aws_violation blocks cp/rm/sync/put/get-object). The
    # upload-a-shell step from the write-up is exploitation and is deliberately not offered here.
    endpoint = f"http://{endpoint_host}"
    commands = [
        Command(
            "s3",
            f"aws --endpoint={endpoint} s3 ls",
            "List S3 buckets on the endpoint (read-only; needs `aws configure` set to anything).",
            "< 30s",
            "s3/buckets.txt",
        )
    ]
    if bucket:
        commands.append(
            Command(
                "s3",
                f"aws --endpoint={endpoint} s3 ls s3://{bucket}",
                f"List objects/prefixes in the {bucket} bucket (read-only).",
                "< 30s",
                f"s3/objects-{bucket}.txt",
            )
        )
    return commands


class S3Module(Module):
    name = "s3"

    def triggers(self, scan_results: ScanResults) -> bool:
        # S3 (localstack/minio behind a vhost) is discovered by subdomain/HTTP signature, not by an
        # nmap port — so it never auto-triggers on ports; the vhost module surfaces it instead.
        return False

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return []

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for sf in parse_s3_tool(tool, text):
                findings.append(
                    Finding(
                        service="s3",
                        title=f"{sf.kind}: {sf.value}",
                        detail=sf.detail,
                        proto=Proto.TCP,
                        fields={"kind": sf.kind, "value": sf.value, "detail": sf.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        buckets = sorted(
            {f.fields.get("value", "") for f in findings if f.fields.get("kind") == "bucket"}
        )
        return [
            f"Readable bucket '{bucket}' — list its objects (read-only): "
            f"aws --endpoint=http://<s3-host> s3 ls s3://{bucket}"
            for bucket in buckets
            if bucket
        ]
