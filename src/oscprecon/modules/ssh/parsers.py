from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

_AUTH_METHODS = frozenset(
    {
        "publickey",
        "password",
        "keyboard-interactive",
        "gssapi-with-mic",
        "gssapi-keyex",
        "hostbased",
        "none",
    }
)


@dataclass
class SshFinding:
    kind: str  # banner | hostkey | algo-weak | auth
    value: str
    detail: str = ""
    module: str = "ssh"

    def to_dict(self, discovered_at: str) -> dict[str, Any]:
        return {
            "module": self.module,
            "kind": self.kind,
            "value": self.value,
            "detail": self.detail,
            "discovered_at": discovered_at,
        }


# `22/tcp open  ssh  OpenSSH 7.6p1 Ubuntu ...` — capture the version/product tail verbatim.
_SSH_VER = re.compile(r"^\d+/tcp[^\S\n]+open[^\S\n]+ssh[-\w]*[^\S\n]+(?P<ver>\S.*)$", re.MULTILINE)
# a host-key line, `| ` prefix stripped: `2048 aa:bb:..:99 (RSA)` or `256 SHA256:… (ED25519)`.
_HOSTKEY = re.compile(r"^(?P<bits>\d+)\s+(?P<fp>\S+)\s+\((?P<type>[^)]+)\)$")


def _is_weak_algo(token: str) -> bool:
    # why: only flag tokens matching a known-weak pattern so bare non-algo lines ("none",
    # "password", "publickey") and modern algos (aes128-ctr, chacha20-…) never false-positive.
    if not token or ":" in token or " " in token:
        return False
    if token.endswith("-cbc") or "3des" in token or token.startswith(("arcfour", "hmac-md5")):
        return True
    return token in {
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group-exchange-sha1",
        "ssh-dss",
    }


def parse_nmap_ssh(text: str) -> list[SshFinding]:
    findings: list[SshFinding] = []
    version = _SSH_VER.search(text)
    if version is not None:
        findings.append(SshFinding("banner", version.group("ver").strip()))

    auth_methods: list[str] = []
    in_auth = False
    for raw in text.splitlines():
        line = re.sub(r"^\|[_ ]?", "", raw).strip()  # drop nmap's "| "/"|_" script-output prefix
        hostkey = _HOSTKEY.match(line)
        if hostkey is not None:
            findings.append(
                SshFinding("hostkey", f"{hostkey.group('type')} {hostkey.group('bits')}", line)
            )
            in_auth = False
            continue
        if "Supported authentication methods" in line:
            in_auth = True
            continue
        if in_auth:
            token = line.rstrip(":").strip()
            if token in _AUTH_METHODS:
                auth_methods.append(token)
                continue
            in_auth = False  # first non-method line ends the auth block
        if _is_weak_algo(line):
            findings.append(SshFinding("algo-weak", line, "weak SSH algorithm offered"))

    for method in dict.fromkeys(auth_methods):
        detail = "password authentication enabled" if method == "password" else ""
        findings.append(SshFinding("auth", method, detail))
    return findings


_PARSERS = {"nmap-ssh": parse_nmap_ssh}


def parse_ssh_tool(tool: str, text: str) -> list[SshFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
