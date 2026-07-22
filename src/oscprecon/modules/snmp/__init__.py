from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.snmp.parsers import (
    SnmpFinding,
    parse_nmap_snmp,
    parse_onesixtyone,
    parse_snmp_tool,
    parse_snmpwalk,
)

__all__ = [
    "SNMP_SERVICE_NAMES",
    "SnmpFinding",
    "SnmpModule",
    "SnmpStep",
    "parse_nmap_snmp",
    "parse_onesixtyone",
    "parse_snmp_tool",
    "parse_snmpwalk",
]

SNMP_SERVICE_NAMES = frozenset({"snmp"})
_SNMP_PORTS = frozenset({161})
# §2 allows onesixtyone with a SMALL community list — the 822-byte onesixtyone-formatted list,
# not the 22 KB snmp-onesixtyone.txt. Community enumeration is recon, not credential brute (§2).
_COMMUNITY_LIST = "/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt"


@dataclass
class SnmpStep:
    command: Command
    tool: str = ""  # parser key for the output, or "" when the output is not parsed


class SnmpModule(Module):
    name = "snmp"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in SNMP_SERVICE_NAMES or s.port in _SNMP_PORTS
            for s in scan_results.services
        )

    def discovery_steps(self, target: Target, port: int = 161) -> list[SnmpStep]:
        host = target.ip
        return [
            SnmpStep(
                Command(
                    "snmp",
                    f"onesixtyone -c {_COMMUNITY_LIST} {host}",
                    "Enumerate valid community strings from a small default list (read-only).",
                    "< 30s",
                    "snmp/onesixtyone.txt",
                ),
                "onesixtyone",
            ),
            SnmpStep(
                Command(
                    "snmp",
                    f"nmap -sU -sV --script snmp-info,snmp-sysdescr,snmp-interfaces,"
                    f"snmp-processes,snmp-netstat -p {port} {host}",
                    "SNMP NSE: sysDescr, engine info, interfaces, processes, netstat (no brute).",
                    "1-5 min",
                    "snmp/nmap-snmp.txt",
                ),
                "nmap-snmp",
            ),
        ]

    def walk_step(self, target: Target, community: str = "public") -> SnmpStep:
        # why: community is an untrusted token reaching a command line — a discovered value
        # (onesixtyone echoes hits verbatim, and the shipped list holds valid space-bearing entries
        # like "all private") or a GUI/Tier-2 entry. shlex.quote keeps it a single argv token so a
        # space can't redirect the walk to another agent or smuggle a flag; the on-disk slug is
        # sanitized separately so a '/' can't escape the profile's snmp/ dir.
        safe = shlex.quote(community)
        slug = re.sub(r"[^A-Za-z0-9._-]", "_", community) or "community"
        return SnmpStep(
            Command(
                "snmp",
                f"snmpwalk -v2c -c {safe} {target.ip}",
                f"Full MIB walk with community '{community}' — system, users, processes, software.",
                "1-5 min",
                f"snmp/snmpwalk-{slug}.txt",
            ),
            "snmpwalk",
        )

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        steps = self.discovery_steps(target) + [self.walk_step(target)]
        return [step.command for step in steps]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for sf in parse_snmp_tool(tool, text):
                findings.append(
                    Finding(
                        service="snmp",
                        title=f"{sf.kind}: {sf.value}",
                        detail=sf.detail,
                        fields={"kind": sf.kind, "value": sf.value, "detail": sf.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        out: list[str] = []
        communities = [
            f.fields.get("value", "") for f in findings if f.fields.get("kind") == "community"
        ]
        extra = [c for c in communities if c and c != "public"]
        if extra:
            out.append(
                f"Non-default SNMP community '{extra[0]}' valid — "
                f"snmpwalk -v2c -c {shlex.quote(extra[0])} {{target}} for the full MIB (recon)."
            )
        users = [f.fields.get("value", "") for f in findings if f.fields.get("kind") == "user"]
        if users:
            out.append(
                f"SNMP leaked {len(users)} account name(s) (e.g. {users[0]}) — "
                "feed them to SMB/LDAP/kerberos user enumeration."
            )
        if any(
            f.fields.get("kind") == "note" and "credential" in f.fields.get("value", "")
            for f in findings
        ):
            out.append(
                "A value over SNMP looks like a credential (in process args, or a system field "
                "like sysContact — HTB Conceal leaks the IKE PSK there) — read the raw snmpwalk "
                "output; do not rely on the redacted finding. A PSK/NTLM-looking 32-hex string "
                "cracks offline (hashkiller/hashcat -m 1000) and can unlock an IKE/IPsec tunnel."
            )
        return out
