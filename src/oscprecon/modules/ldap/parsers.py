from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

# why: defaultNamingContext is intentionally absent — it is already surfaced as a naming-context
# finding, so listing it here too would duplicate it.
_INFO_ATTRS = (
    "dnsHostName",
    "rootDomainNamingContext",
    "domainFunctionality",
    "forestFunctionality",
    "domainControllerFunctionality",
    "serverName",
)


@dataclass
class LdapFinding:
    kind: str  # naming-context | info | user | bind
    value: str
    detail: str = ""
    module: str = "ldap"

    def to_dict(self, discovered_at: str) -> dict[str, Any]:
        return {
            "module": self.module,
            "kind": self.kind,
            "value": self.value,
            "detail": self.detail,
            "discovered_at": discovered_at,
        }


def _unfold(text: str) -> list[str]:
    # LDIF folds long values onto continuation lines that begin with a single space — rejoin them
    # so an attribute's full value is on one logical line before we read it.
    lines: list[str] = []
    for raw in text.splitlines():
        if raw.startswith(" ") and lines:
            lines[-1] += raw[1:]
        else:
            lines.append(raw)
    return lines


def _ldif_values(lines: list[str], attr: str) -> list[str]:
    wanted = attr.lower()
    out: list[str] = []
    for line in lines:
        key, sep, val = line.partition(":")
        if not sep or key.strip().lower() != wanted:
            continue
        val = val.strip()
        if val.startswith(":"):  # `attr:: base64value` — skip base64 (not needed for these attrs)
            continue
        if val:
            out.append(val)
    return out


def parse_ldapsearch_rootdse(text: str) -> list[LdapFinding]:
    lines = _unfold(text)
    findings: list[LdapFinding] = []
    contexts: list[str] = []
    for nc in _ldif_values(lines, "namingContexts") + _ldif_values(lines, "defaultNamingContext"):
        if nc not in contexts:
            contexts.append(nc)
    for nc in contexts:
        findings.append(LdapFinding("naming-context", nc))
    for attr in _INFO_ATTRS:
        for value in _ldif_values(lines, attr):
            findings.append(LdapFinding("info", f"{attr}: {value}"))
    if contexts:  # a root DSE came back over an anonymous (-x) bind
        findings.append(
            LdapFinding(
                "bind", "anonymous", "anonymous bind returns the root DSE / naming contexts"
            )
        )
    return findings


def parse_ldapsearch_entries(text: str) -> list[LdapFinding]:
    lines = _unfold(text)
    findings: list[LdapFinding] = []
    seen: list[str] = []
    for user in _ldif_values(lines, "sAMAccountName"):
        if user not in seen:
            seen.append(user)
            findings.append(LdapFinding("user", user))
    return findings


# nmap ldap-rootdse prints `|   namingContexts: DC=example,DC=htb` under the script block.
_NMAP_NC = re.compile(r"namingContexts:\s*(?P<nc>\S.*?)\s*$", re.MULTILINE)
_NMAP_HOST = re.compile(r"dnsHostName:\s*(?P<host>\S.*?)\s*$", re.MULTILINE)


def parse_nmap_ldap(text: str) -> list[LdapFinding]:
    findings: list[LdapFinding] = []
    seen: list[str] = []
    for match in _NMAP_NC.finditer(text):
        nc = match.group("nc").strip()
        if nc not in seen:
            seen.append(nc)
            findings.append(LdapFinding("naming-context", nc))
    host = _NMAP_HOST.search(text)
    if host is not None:
        findings.append(LdapFinding("info", f"dnsHostName: {host.group('host').strip()}"))
    return findings


_PARSERS = {
    "ldapsearch-rootdse": parse_ldapsearch_rootdse,
    "ldapsearch-users": parse_ldapsearch_entries,
    "nmap-ldap": parse_nmap_ldap,
}


def parse_ldap_tool(tool: str, text: str) -> list[LdapFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
