from __future__ import annotations

import re
from dataclasses import dataclass

from oscprecon.models import Command, Credential, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.ldap.parsers import (
    LdapFinding,
    parse_ldap_tool,
    parse_ldapsearch_entries,
    parse_ldapsearch_rootdse,
    parse_nmap_ldap,
)
from oscprecon.recon_auth import ReconAuth

__all__ = [
    "LDAP_SERVICE_NAMES",
    "LDAPS_PORTS",
    "LdapFinding",
    "LdapModule",
    "LdapStep",
    "anon_credential",
    "domain_to_basedn",
    "ldap_uri",
    "parse_ldap_tool",
    "parse_ldapsearch_entries",
    "parse_ldapsearch_rootdse",
    "parse_nmap_ldap",
    "sanitize_basedn",
]

LDAP_SERVICE_NAMES = frozenset({"ldap", "ldaps", "globalcatldap", "globalcatldapssl", "msft-gc"})
LDAPS_PORTS = frozenset({636, 3269})
_LDAP_PORTS = frozenset({389, 636, 3268, 3269})
_USER_SEARCH_LIMIT = 200  # -z cap so an anonymous dump stays a bounded recon snapshot (§12)

# a base DN is `RDN,RDN,...` (e.g. DC=example,DC=htb / CN=Domain Admins,DC=example,DC=htb). Accept
# only DN-syntax characters so a user-typed OR server-returned value can never break the `-b "..."`
# quoting or inject a flag; the leading char must be alphanumeric (no leading '-').
_BASEDN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9=,. _-]*$")


@dataclass
class LdapStep:
    command: Command
    tool: str = ""  # parser key for the output, or "" when the output is not parsed


def ldap_uri(host: str, port: int) -> str:
    scheme = "ldaps" if port in LDAPS_PORTS else "ldap"
    return f"{scheme}://{host}:{port}"


def sanitize_basedn(value: str | None) -> str | None:
    if not value:
        return None
    candidate = value.strip()
    return candidate if _BASEDN_RE.match(candidate) else None


def domain_to_basedn(domain: str | None) -> str:
    # example.htb -> DC=example,DC=htb (only for clean label.label domains; else empty)
    if not domain:
        return ""
    labels = [label for label in domain.strip().split(".") if label]
    if not labels or not all(re.fullmatch(r"[A-Za-z0-9-]+", label) for label in labels):
        return ""
    return ",".join(f"DC={label}" for label in labels)


def anon_credential(target: Target) -> Credential:
    return Credential(
        username="anonymous",
        secret="",
        secret_type="password",
        domain=target.hostname or "",
        source="ldap-anon-enum",
        notes="Anonymous LDAP bind returns directory data",
    )


class LdapModule(Module):
    name = "ldap"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in LDAP_SERVICE_NAMES or s.port in _LDAP_PORTS
            for s in scan_results.services
        )

    def rootdse_steps(
        self, target: Target, port: int = 389, auth: ReconAuth | None = None
    ) -> list[LdapStep]:
        host = target.ip
        uri = ldap_uri(host, port)
        who = auth or ReconAuth.null()
        bind = who.ldapsearch_args()
        base = "ldap" if who.anonymous else f"ldap/{who.output_slug}"
        label = "Anonymous" if who.anonymous else f"As {who.label}:"
        return [
            LdapStep(
                Command(
                    "ldap",
                    f'ldapsearch {bind} -H {uri} -s base -b "" "(objectClass=*)" +',
                    f"{label} root DSE — naming contexts, DC hostname, functional levels (recon).",
                    "< 30s",
                    f"{base}/rootdse.txt",
                ),
                "ldapsearch-rootdse",
            ),
            LdapStep(
                Command(
                    "ldap",
                    f"nmap -sV --script ldap-rootdse -p {port} {host}",
                    "Banner plus root DSE via NSE (recon).",
                    "< 1 min",
                    "ldap/nmap-ldap.txt",
                ),
                "nmap-ldap",
            ),
        ]

    def user_search_step(
        self, target: Target, basedn: str, port: int = 389, auth: ReconAuth | None = None
    ) -> LdapStep | None:
        clean = sanitize_basedn(basedn)
        if clean is None:
            return None
        uri = ldap_uri(target.ip, port)
        who = auth or ReconAuth.null()
        base = "ldap" if who.anonymous else f"ldap/{who.output_slug}"
        label = "anonymous" if who.anonymous else f"authenticated ({who.label})"
        return LdapStep(
            Command(
                "ldap",
                f'ldapsearch {who.ldapsearch_args()} -H {uri} -b "{clean}" "(objectClass=person)" '
                f"sAMAccountName cn -z {_USER_SEARCH_LIMIT}",
                f"Bounded {label} user enumeration under the discovered base DN (recon).",
                "< 1 min",
                f"{base}/users.txt",
            ),
            "ldapsearch-users",
        )

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.rootdse_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for lf in parse_ldap_tool(tool, text):
                findings.append(
                    Finding(
                        service="ldap",
                        title=f"{lf.kind}: {lf.value}",
                        detail=lf.detail,
                        fields={"kind": lf.kind, "value": lf.value, "detail": lf.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        out: list[str] = []
        if any(f.fields.get("kind") == "bind" for f in findings):
            out.append(
                "Anonymous LDAP read allowed — enumerate users/groups/computers, and check user "
                "description fields for plaintext secrets (recon)."
            )
        contexts = [
            f.fields.get("value", "") for f in findings if f.fields.get("kind") == "naming-context"
        ]
        if contexts:
            out.append(
                f"Base DN {contexts[0]} — pivot every anonymous query off it (Tier-2 follow-ups)."
            )
        users = [f for f in findings if f.fields.get("kind") == "user"]
        if users:
            out.append(
                f"{len(users)} users via anonymous LDAP — feed them to the SMB/kerberos modules."
            )
        return out
