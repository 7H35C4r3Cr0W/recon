from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from oscprecon.modules.nxc_auth import parse_login_verdict


@dataclass
class MssqlFinding:
    kind: str  # version | instance | hostname | domain | os-build
    value: str
    detail: str = ""
    module: str = "mssql"

    def to_dict(self, discovered_at: str) -> dict[str, Any]:
        return {
            "module": self.module,
            "kind": self.kind,
            "value": self.value,
            "detail": self.detail,
            "discovered_at": discovered_at,
        }


# A missing/blocked wrapped tool writes a sentinel line to the output file (shell.run) — skip those.
_SENTINEL = ("[missing]", "[blocked]")

# ms-sql-info + ms-sql-ntlm-info are unauth pre-login leaks; fields below map that nmap NSE output.
# why: [ \t]+ (not \s+) so the service name and its version must share one physical line — \s+ spans
# the newline and captures the following ntlm-info header as a bogus version on a bare -sV line.
_VERSION_LINE = re.compile(r"ms-sql-s[ \t]+(?P<v>.+?)\s*$", re.MULTILINE)
_PRODUCT = re.compile(r"\bProduct:\s*(?P<v>.+?)\s*$", re.MULTILINE)
_NUMBER = re.compile(r"\bnumber:\s*(?P<v>[\d.]+)\s*$", re.MULTILINE)
_INSTANCE = re.compile(r"Instance name:\s*(?P<v>.+?)\s*$", re.MULTILINE)
_SRV_NAME = re.compile(r"Windows server name:\s*(?P<v>.+?)\s*$", re.MULTILINE)
_NETBIOS_COMPUTER = re.compile(r"NetBIOS_Computer_Name:\s*(?P<v>.+?)\s*$", re.MULTILINE)
_NETBIOS_DOMAIN = re.compile(r"NetBIOS_Domain_Name:\s*(?P<v>.+?)\s*$", re.MULTILINE)
_DNS_DOMAIN = re.compile(r"DNS_Domain_Name:\s*(?P<v>.+?)\s*$", re.MULTILINE)
_OS_BUILD = re.compile(r"Product_Version:\s*(?P<v>[\d.]+)\s*$", re.MULTILINE)


def _first(rx: re.Pattern[str], text: str) -> str:
    match = rx.search(text)
    return match.group("v").strip() if match is not None else ""


def _version_from(text: str) -> str:
    # prefer the structured ms-sql-info Product + number, else the bare -sV service line.
    product, number = _first(_PRODUCT, text), _first(_NUMBER, text)
    if product and number:
        return f"{product} {number}"
    if product:
        return product
    return _first(_VERSION_LINE, text)


def parse_mssql_info(text: str) -> list[MssqlFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    findings: list[MssqlFinding] = []
    hostname = _first(_SRV_NAME, text) or _first(_NETBIOS_COMPUTER, text)
    # ms-sql-info emits one block per instance, each with its own Instance name / Product / number.
    # Slice the text at each "Instance name:" boundary so a multi-instance host surfaces every
    # instance + version, not just the first.
    instances = list(_INSTANCE.finditer(text))
    for idx, match in enumerate(instances):
        end = instances[idx + 1].start() if idx + 1 < len(instances) else len(text)
        findings.append(MssqlFinding("instance", match.group("v").strip()))
        version = _version_from(text[match.start() : end])
        if version:
            findings.append(MssqlFinding("version", version))
    # no per-instance version (ms-sql-info absent/blocked) — fall back to a host-wide version read.
    if not any(f.kind == "version" for f in findings):
        version = _version_from(text)
        if version:
            findings.append(MssqlFinding("version", version))
    if hostname:
        findings.append(MssqlFinding("hostname", hostname))
    # domain: prefer the DNS FQDN (the real domain-joined signal). A standalone box reports
    # NetBIOS_Domain_Name == computer name or the literal WORKGROUP — neither is an AD domain.
    domain = _first(_DNS_DOMAIN, text) or _first(_NETBIOS_DOMAIN, text)
    if domain and domain.upper() != "WORKGROUP" and domain.lower() != hostname.lower():
        findings.append(MssqlFinding("domain", domain, "AD domain (from NTLM info)"))
    os_build = _first(_OS_BUILD, text)
    if os_build:
        findings.append(MssqlFinding("os-build", os_build, "Windows build (from NTLM info)"))
    return findings


def parse_login(text: str) -> list[MssqlFinding]:
    return [MssqlFinding(kind, value, detail) for kind, value, detail in parse_login_verdict(text)]


_PARSERS = {"mssql-login": parse_login, "mssql-info": parse_mssql_info}


def parse_mssql_tool(tool: str, text: str) -> list[MssqlFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
