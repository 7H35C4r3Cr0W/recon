from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class SmbFinding:
    kind: str  # auth | signing | share | user | policy | note
    value: str
    detail: str = ""
    module: str = "smb"

    def to_dict(self, discovered_at: str) -> dict[str, Any]:
        return {
            "module": self.module,
            "kind": self.kind,
            "value": self.value,
            "detail": self.detail,
            "discovered_at": discovered_at,
        }


# netexec lines are prefixed "SMB <host> <port> <NAME>  <rest>"; strip that to reach the content.
_NXC_PREFIX = re.compile(r"^SMB\s+\S+\s+\d+\s+\S+\s+(?P<rest>.*)$")


def _nxc_rest(line: str) -> str | None:
    match = _NXC_PREFIX.match(line)
    return match.group("rest").rstrip() if match is not None else None


def netexec_auth_ok(text: str) -> bool:
    for line in text.splitlines():
        rest = _nxc_rest(line)
        if rest is not None and rest.startswith("[+]"):
            return True
    return False


def parse_netexec_shares(text: str) -> list[SmbFinding]:
    findings: list[SmbFinding] = []
    in_table = False
    for line in text.splitlines():
        rest = _nxc_rest(line)
        if rest is None:
            continue
        signing = re.search(r"signing:(True|False)", rest)
        if signing is not None:
            findings.append(
                SmbFinding("signing", "enabled" if signing.group(1) == "True" else "disabled")
            )
        if rest.startswith("[+]"):
            findings.append(SmbFinding("auth", "authenticated", rest[3:].strip()))
            continue
        if rest.startswith("Share") and "Permissions" in rest:
            in_table = True
            continue
        if rest.startswith("---"):
            continue
        if in_table:
            if rest.startswith("["):
                in_table = False
                continue
            tokens = rest.split()
            if not tokens:
                in_table = False
                continue
            perms = [t for t in tokens[1:] if t in ("READ", "WRITE")]
            findings.append(SmbFinding("share", tokens[0], ",".join(perms)))
    return findings


_DOMAIN_USER = re.compile(r"^[^\\\s]+\\(?P<user>\S+)")


def parse_netexec_users(text: str) -> list[SmbFinding]:
    findings: list[SmbFinding] = []
    for line in text.splitlines():
        rest = _nxc_rest(line)
        if rest is None or rest.startswith("["):
            continue
        match = _DOMAIN_USER.match(rest)
        if match is not None:
            findings.append(SmbFinding("user", match.group("user")))
    return findings


_RID_USER = re.compile(r"^\d+:\s+\S+\\(?P<name>.+?)\s+\(SidTypeUser\)")


def parse_netexec_ridbrute(text: str) -> list[SmbFinding]:
    findings: list[SmbFinding] = []
    for line in text.splitlines():
        rest = _nxc_rest(line)
        if rest is None:
            continue
        match = _RID_USER.match(rest)
        if match is not None:
            findings.append(SmbFinding("user", match.group("name"), "rid-brute"))
    return findings


def parse_netexec_passpol(text: str) -> list[SmbFinding]:
    findings: list[SmbFinding] = []
    for line in text.splitlines():
        rest = _nxc_rest(line)
        if rest is None or rest.startswith("[") or ":" not in rest:
            continue
        key, _, value = rest.partition(":")
        key = key.strip()
        if key.lower() in (
            "minimum password length",
            "password history length",
            "account lockout threshold",
            "maximum password age",
        ):
            findings.append(SmbFinding("policy", key, value.strip()))
    return findings


def parse_smbclient_shares(text: str) -> list[SmbFinding]:
    findings: list[SmbFinding] = []
    in_table = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("Sharename"):
            in_table = True
            continue
        if stripped.startswith("---"):
            continue
        if in_table:
            if not stripped or stripped.startswith("SMB1") or stripped.startswith("Server"):
                in_table = False
                continue
            tokens = stripped.split()
            if tokens:
                findings.append(SmbFinding("share", tokens[0]))
    return findings


_RPC_USER = re.compile(r"user:\[(?P<name>[^\]]+)\]")


def parse_rpcclient_users(text: str) -> list[SmbFinding]:
    findings: list[SmbFinding] = []
    for line in text.splitlines():
        match = _RPC_USER.search(line)
        if match is not None:
            findings.append(SmbFinding("user", match.group("name")))
    return findings


_PARSERS = {
    "netexec-shares": parse_netexec_shares,
    "netexec-users": parse_netexec_users,
    "netexec-ridbrute": parse_netexec_ridbrute,
    "netexec-passpol": parse_netexec_passpol,
    "smbclient-shares": parse_smbclient_shares,
    "rpcclient-users": parse_rpcclient_users,
}


def parse_smb_tool(tool: str, text: str) -> list[SmbFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []


def readable_shares(findings: list[SmbFinding]) -> list[str]:
    return [f.value for f in findings if f.kind == "share" and "READ" in f.detail]
