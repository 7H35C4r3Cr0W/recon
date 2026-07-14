from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class RdpFinding:
    kind: str  # version | hostname | domain | os-build | nla | encryption
    value: str
    detail: str = ""
    module: str = "rdp"

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

# rdp-ntlm-info leaks the AD identity pre-auth; rdp-enum-encryption reveals the security layer.
_NETBIOS_COMPUTER = re.compile(r"NetBIOS_Computer_Name:\s*(?P<v>.+?)\s*$", re.MULTILINE)
_NETBIOS_DOMAIN = re.compile(r"NetBIOS_Domain_Name:\s*(?P<v>.+?)\s*$", re.MULTILINE)
_DNS_COMPUTER = re.compile(r"DNS_Computer_Name:\s*(?P<v>.+?)\s*$", re.MULTILINE)
_DNS_DOMAIN = re.compile(r"DNS_Domain_Name:\s*(?P<v>.+?)\s*$", re.MULTILINE)
_TARGET_NAME = re.compile(r"Target_Name:\s*(?P<v>.+?)\s*$", re.MULTILINE)
_PRODUCT_VERSION = re.compile(r"Product_Version:\s*(?P<v>[\d.]+)\s*$", re.MULTILINE)
_ENC_LEVEL = re.compile(r"RDP Encryption level:\s*(?P<v>.+?)\s*$", re.MULTILINE)
_PROTO_VERSION = re.compile(r"RDP Protocol Version:\s*(?P<v>[\d.]+)\s*$", re.MULTILINE)
# -sV service line fallback (ms-wbt-server), e.g. "3389/tcp open ms-wbt-server Microsoft Terminal…".
_SV_LINE = re.compile(r"ms-wbt-server[ \t]+(?P<v>.+?)\s*$", re.MULTILINE)


def _first(rx: re.Pattern[str], text: str) -> str:
    match = rx.search(text)
    return match.group("v").strip() if match is not None else ""


def _layer_result(label: str, text: str) -> str:
    match = re.search(rf"{re.escape(label)}:\s*(?P<v>SUCCESS|FAILED)", text)
    return match.group("v") if match is not None else ""


def parse_rdp_info(text: str) -> list[RdpFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    findings: list[RdpFinding] = []

    hostname = _first(_DNS_COMPUTER, text) or _first(_NETBIOS_COMPUTER, text)
    if hostname:
        findings.append(RdpFinding("hostname", hostname))

    # domain: prefer the DNS FQDN. A standalone box reports the domain == host name or WORKGROUP.
    domain = (
        _first(_DNS_DOMAIN, text) or _first(_NETBIOS_DOMAIN, text) or _first(_TARGET_NAME, text)
    )
    host_short = hostname.split(".")[0].lower()
    if domain and domain.upper() != "WORKGROUP" and domain.split(".")[0].lower() != host_short:
        findings.append(RdpFinding("domain", domain, "AD domain (from RDP NTLM info)"))

    os_build = _first(_PRODUCT_VERSION, text)
    if os_build:
        findings.append(RdpFinding("os-build", os_build, "Windows build (from RDP NTLM info)"))

    # NLA (CredSSP): if only Native RDP is accepted and CredSSP is not, the login screen is
    # reachable without a prior credential — a recon signal, not an exploit.
    credssp = _layer_result("CredSSP (NLA)", text)
    native = _layer_result("Native RDP", text)
    if credssp == "SUCCESS" and native != "SUCCESS":
        findings.append(RdpFinding("nla", "enforced", "CredSSP/NLA required before the desktop"))
    elif native == "SUCCESS" and credssp != "SUCCESS":
        findings.append(
            RdpFinding("nla", "not-enforced", "Native RDP accepted without CredSSP/NLA")
        )
    elif credssp == "SUCCESS" and native == "SUCCESS":
        findings.append(RdpFinding("nla", "optional", "both Native RDP and CredSSP/NLA accepted"))

    enc = _first(_ENC_LEVEL, text)
    if enc:
        findings.append(RdpFinding("encryption", enc, "RDP encryption level"))

    proto = _first(_PROTO_VERSION, text)
    if proto:
        findings.append(RdpFinding("version", f"RDP protocol {proto}"))
    elif not os_build:  # only fall back to the bare -sV product when NTLM info was absent
        sv = _first(_SV_LINE, text)
        if sv:
            findings.append(RdpFinding("version", sv))
    return findings


_PARSERS = {"rdp-info": parse_rdp_info}


def parse_rdp_tool(tool: str, text: str) -> list[RdpFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
