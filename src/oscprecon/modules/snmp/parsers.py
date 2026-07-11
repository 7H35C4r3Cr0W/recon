from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class SnmpFinding:
    kind: str  # community | banner | user | process | interface | note
    value: str
    detail: str = ""
    module: str = "snmp"

    def to_dict(self, discovered_at: str) -> dict[str, Any]:
        return {
            "module": self.module,
            "kind": self.kind,
            "value": self.value,
            "detail": self.detail,
            "discovered_at": discovered_at,
        }


# onesixtyone prints one line per (host, valid community): `IP [community] sysDescr...`.
_ONESIXTYONE = re.compile(
    r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\[(?P<comm>[^\]]+)\]\s*(?P<desc>.*)$", re.MULTILINE
)
# credentials frequently sit in process command-line args exposed over SNMP — flag their presence
# WITHOUT copying the secret into a finding (§6: reports/findings never carry plaintext secrets).
_CRED_HINT = re.compile(r"(?<![A-Za-z])pass(?:word|wd)?\s*[=:]", re.IGNORECASE)


def _dedup(findings: list[SnmpFinding]) -> list[SnmpFinding]:
    seen: set[tuple[str, str]] = set()
    out: list[SnmpFinding] = []
    for f in findings:
        key = (f.kind, f.value)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def parse_onesixtyone(text: str) -> list[SnmpFinding]:
    findings: list[SnmpFinding] = []
    for match in _ONESIXTYONE.finditer(text):
        community = match.group("comm").strip()
        if community:
            findings.append(SnmpFinding("community", community, "valid SNMP community (read)"))
        desc = match.group("desc").strip()
        if desc:
            findings.append(SnmpFinding("banner", desc))
    return _dedup(findings)


_SNMP_VER = re.compile(r"^\d+/udp\s+open\s+snmp\S*\s+(?P<ver>\S.*)$", re.MULTILINE)


def parse_nmap_snmp(text: str) -> list[SnmpFinding]:
    findings: list[SnmpFinding] = []
    version = _SNMP_VER.search(text)
    if version is not None:
        findings.append(SnmpFinding("banner", version.group("ver").strip()))
    for raw in text.splitlines():
        line = re.sub(r"^\|[_ ]?", "", raw).strip()  # strip nmap's "| "/"|_" script prefix
        low = line.lower()
        if low.startswith("snmp-sysdescr:"):
            desc = line.split(":", 1)[1].strip()
            if desc:
                findings.append(SnmpFinding("banner", desc))
        elif low.startswith("name:"):  # snmp-processes / snmp-win32-services entry
            name = line.split(":", 1)[1].strip()
            if name:
                findings.append(SnmpFinding("process", name))
        elif low.startswith("ip address:"):
            ip = line.split(":", 1)[1].strip().split()[0] if line.split(":", 1)[1].strip() else ""
            if ip:
                findings.append(SnmpFinding("interface", ip))
        elif low.startswith("enterprise:"):
            ent = line.split(":", 1)[1].strip()
            if ent:
                findings.append(SnmpFinding("note", f"SNMP enterprise: {ent}"))
    return _dedup(findings)


# Well-known OIDs worth pulling out of a full walk. snmpwalk renders these with MIB names when MIBs
# are loaded (sysDescr / hrSWRunName) but as raw numbers otherwise, and net-snmp prints `iso` for
# the leading `.1` — so numeric matches use the distinctive prefix-independent tail, not a full OID.
_USER_OID = ".77.1.2.25"  # Microsoft LanMgr user-account table (enterprise 77)
_PROC_OID = ".25.4.2.1.2."  # hrSWRunName (host-resources running software)
_SYSDESCR_TAIL = ".1.2.1.1.1.0"  # system.sysDescr.0


def parse_snmpwalk(text: str) -> list[SnmpFinding]:
    findings: list[SnmpFinding] = []
    for raw in text.splitlines():
        oid, sep, rest = raw.strip().partition(" = ")
        if not sep:
            continue
        value = (rest.split(":", 1)[1].strip() if ":" in rest else rest.strip()).strip('"')
        if not value:
            continue
        low_oid = oid.lower()
        if "sysdescr" in low_oid or oid.endswith(_SYSDESCR_TAIL):
            findings.append(SnmpFinding("banner", value))
        elif _USER_OID in oid:  # Windows account names
            findings.append(SnmpFinding("user", value))
        elif "hrswrunname" in low_oid or _PROC_OID in oid:
            findings.append(SnmpFinding("process", value))
    if _CRED_HINT.search(text):
        findings.append(
            SnmpFinding(
                "note",
                "possible credential in SNMP data",
                "a value (e.g. process args) looks like it holds a password — read the raw "
                "snmpwalk output; the secret is deliberately not copied here",
            )
        )
    return _dedup(findings)


_PARSERS = {
    "onesixtyone": parse_onesixtyone,
    "nmap-snmp": parse_nmap_snmp,
    "snmpwalk": parse_snmpwalk,
}


def parse_snmp_tool(tool: str, text: str) -> list[SnmpFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
