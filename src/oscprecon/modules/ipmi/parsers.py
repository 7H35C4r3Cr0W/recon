from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class IpmiFinding:
    kind: str  # version | auth | cipher-zero
    value: str
    detail: str = ""
    module: str = "ipmi"

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

_VERSION = re.compile(r"IPMI-(?P<v>\d+\.\d+)")
_USERAUTH = re.compile(r"UserAuth:\s*(?P<v>.+?)\s*$", re.MULTILINE)
# ipmi-cipher-zero flags the misconfig with an nmap VULNERABLE/State block.
_CIPHER0 = re.compile(r"cipher[\s-]*zero", re.IGNORECASE)
_VULN_STATE = re.compile(r"State:\s*VULNERABLE|VULNERABLE:", re.IGNORECASE)


def parse_ipmi_info(text: str) -> list[IpmiFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    findings: list[IpmiFinding] = []

    versions = sorted({m.group("v") for m in _VERSION.finditer(text)})
    if versions:
        findings.append(IpmiFinding("version", ", ".join(versions), "supported IPMI levels"))

    userauth = _USERAUTH.search(text)
    if userauth is not None and userauth.group("v").strip():
        findings.append(IpmiFinding("auth", userauth.group("v").strip(), "IPMI user-auth flags"))

    # cipher-zero: only flag when the cipher-zero script actually reports the VULNERABLE state, so a
    # bare mention of the script name in a scan header never produces a false positive.
    if _CIPHER0.search(text) and _VULN_STATE.search(text):
        findings.append(
            IpmiFinding("cipher-zero", "enabled", "IPMI Cipher Zero — authentication bypass")
        )
    return findings


_PARSERS = {"ipmi-info": parse_ipmi_info}


def parse_ipmi_tool(tool: str, text: str) -> list[IpmiFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
