from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class KerberosFinding:
    kind: str  # service | server-time | user-no-preauth | spn | user
    value: str
    detail: str = ""
    module: str = "kerberos"

    def to_dict(self, discovered_at: str) -> dict[str, Any]:
        return {
            "module": self.module,
            "kind": self.kind,
            "value": self.value,
            "detail": self.detail,
            "discovered_at": discovered_at,
        }


# `88/tcp open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-06-01 12:34:56Z)`
_KRB_LINE = re.compile(r"^88/tcp\s+open\s+(?P<svc>\S+)(?:\s+(?P<rest>.*\S))?\s*$", re.MULTILINE)
_SERVER_TIME = re.compile(r"server time:\s*(?P<t>[^)]+)")


def parse_nmap_kerberos(text: str) -> list[KerberosFinding]:
    findings: list[KerberosFinding] = []
    line = _KRB_LINE.search(text)
    if line is not None:
        rest = (line.group("rest") or "").strip()
        product = _SERVER_TIME.sub("", rest).strip(" ()") if rest else ""
        findings.append(KerberosFinding("service", line.group("svc"), product))
    when = _SERVER_TIME.search(text)
    if when is not None:
        findings.append(
            KerberosFinding("server-time", when.group("t").strip(), "KDC clock-skew reference")
        )
    return findings


# GetNPUsers prints the AS-REP as `$krb5asrep$<etype>$principal@REALM:<hash>` for each roastable
# account. why: we extract ONLY the principal (the misconfig: no Kerberos pre-auth) — NEVER the hash
# blob, which is cracking material and out of scope (§2). Cracking is the user's separate concern.
_ASREP = re.compile(r"\$krb5asrep\$(?:\d+\$)?(?P<principal>[^:$\s]+@[^:$\s]+):")


def parse_getnpusers(text: str) -> list[KerberosFinding]:
    seen: set[str] = set()
    findings: list[KerberosFinding] = []
    for match in _ASREP.finditer(text):
        principal = match.group("principal")
        if principal in seen:
            continue
        seen.add(principal)
        findings.append(
            KerberosFinding("user-no-preauth", principal, "AS-REP roastable (no Kerberos pre-auth)")
        )
    return findings


# GetUserSPNs prints a table; data rows start with an SPN (contains `/`), then the account name.
# We list the SPN + account (Kerberoastable) — enumeration only; we never wrap `-request` (dump).
_SPN_ROW = re.compile(r"^(?P<spn>\S+/\S+)\s+(?P<name>\S+)")


def parse_getuserspns(text: str) -> list[KerberosFinding]:
    seen: set[str] = set()
    findings: list[KerberosFinding] = []
    for raw in text.splitlines():
        match = _SPN_ROW.match(raw.strip())
        if match is None:
            continue
        spn = match.group("spn")
        if spn in seen:
            continue
        seen.add(spn)
        findings.append(
            KerberosFinding("spn", spn, f"Kerberoastable account: {match.group('name')}")
        )
    return findings


def parse_getadusers(text: str) -> list[KerberosFinding]:
    findings: list[KerberosFinding] = []
    seen: set[str] = set()
    in_table = False
    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        # the header separator is dash-groups, possibly space-separated across columns: `----  ----`
        if stripped and set(stripped) <= {"-", " "} and "---" in stripped:
            in_table = True
            continue
        if not in_table or not line.strip() or line.lstrip().startswith("["):
            continue
        name = line.split()[0]
        if name and name not in seen:
            seen.add(name)
            findings.append(KerberosFinding("user", name, "domain account"))
    return findings


_PARSERS = {
    "nmap-kerberos": parse_nmap_kerberos,
    "getnpusers": parse_getnpusers,
    "getuserspns": parse_getuserspns,
    "getadusers": parse_getadusers,
}


def parse_kerberos_tool(tool: str, text: str) -> list[KerberosFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
