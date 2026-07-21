from __future__ import annotations

import hashlib
import re
import shlex
from dataclasses import dataclass
from urllib.parse import quote

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.tftp.parsers import TftpFinding, parse_nmap_tftp, parse_tftp_tool

__all__ = [
    "COMMON_FILES",
    "TFTP_SERVICE_NAMES",
    "TftpFinding",
    "TftpModule",
    "TftpStep",
    "parse_nmap_tftp",
    "parse_tftp_tool",
    "tftp_get_url",
]

TFTP_SERVICE_NAMES = frozenset({"tftp"})
_TFTP_PORTS = frozenset({69})

# Well-known TFTP-served filenames (network-device configs + common backups). TFTP has no listing
# protocol, so recon is GETting a small fixed list of well-known names — content discovery (§2/§12),
# not a credential/username brute.
COMMON_FILES = (
    # network-device configs (TFTP is blind — no listing — so we GET well-known names)
    "running-config",
    "startup-config",
    "config.text",
    "router.cfg",
    "switch.cfg",
    "backup.cfg",
    "config.bin",
    "nvram.bin",
    "bootrom.ld",
    "version.txt",
    "sysconfig",
    "tftpd.conf",
    # common Linux / service config + secret paths — a TFTP root mounted at / (or a permissive
    # server) serves these by absolute path; grabbing squid.conf/passwd/keys is a classic foothold.
    "/etc/passwd",
    "/etc/shadow",
    "/etc/squid/squid.conf",
    "/etc/squid/passwords",
    "/etc/apache2/apache2.conf",
    "/etc/nginx/nginx.conf",
    "/etc/hosts",
    "/etc/crontab",
    "/root/.ssh/id_rsa",
    "/home/.ssh/id_rsa",
    "/var/www/html/config.php",
    ".htpasswd",
)


@dataclass
class TftpStep:
    command: Command
    tool: str = ""  # parser key for the output, or "" when the output is not parsed


def tftp_get_url(target: str, port: int, filename: str) -> str:
    # why: keep '/' unencoded so a real PATH (e.g. /etc/squid/squid.conf) fetches — a TFTP GET can
    # target a path, and %2F-encoding it (the old bug) asked for a file literally named "%2Fetc%2F…"
    # which never exists. Other chars ARE encoded, and the whole url is shlex.quote'd at the exec
    # chokepoint below, so a target-controlled name still can't smuggle a curl flag or a 2nd URL.
    encoded = quote(filename, safe="/")
    authority = target if port == 69 else f"{target}:{port}"
    return f"tftp://{authority}/{encoded}"


def _file_slug(filename: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "-", filename.strip("/")) or "file"


class TftpModule(Module):
    name = "tftp"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in TFTP_SERVICE_NAMES or s.port in _TFTP_PORTS
            for s in scan_results.services
        )

    def enum_step(self, target: Target, port: int = 69) -> TftpStep:
        return TftpStep(
            Command(
                "tftp",
                f"nmap -sU -sV --script tftp-enum -p {port} {target.ip}",
                "Enumerate readable files from nmap's well-known TFTP list (read-only).",
                "1-5 min",
                "tftp/nmap-tftp.txt",
            ),
            "nmap-tftp",
        )

    def get_step(self, target: Target, filename: str, port: int = 69) -> TftpStep:
        url = tftp_get_url(target.ip, port, filename)
        # why: the slug is lossy (many names collapse to one), so append a hash of the full filename
        # to keep on-disk retrieval snapshots injective.
        digest = hashlib.sha1(filename.encode("utf-8"), usedforsecurity=False).hexdigest()[:8]
        return TftpStep(
            Command(
                "tftp",
                f"curl -s {shlex.quote(url)}",
                f"Attempt TFTP GET of well-known file '{filename}' (no listing — try by name).",
                "< 30s",
                f"tftp/{_file_slug(filename)}-{digest}.txt",
            ),
            "",
        )

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        steps = [self.enum_step(target)] + [self.get_step(target, name) for name in COMMON_FILES]
        return [step.command for step in steps]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for tf in parse_tftp_tool(tool, text):
                findings.append(
                    Finding(
                        service="tftp",
                        title=f"{tf.kind}: {tf.value}",
                        detail=tf.detail,
                        fields={"kind": tf.kind, "value": tf.value, "detail": tf.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        files = [f.fields.get("value", "") for f in findings if f.fields.get("kind") == "file"]
        out: list[str] = []
        if files:
            out.append(
                f"TFTP served {len(files)} file(s) (e.g. {files[0]}) — download and inspect; "
                "network-device configs often hold plaintext / Type-7 secrets and SNMP communities."
            )
        return out
