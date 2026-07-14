from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class MsrpcFinding:
    kind: str  # access | endpoints | pipe | version
    value: str
    detail: str = ""
    module: str = "msrpc"

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

_UUID = re.compile(r"^UUID\s*:", re.MULTILINE | re.IGNORECASE)
_PIPE = re.compile(r"\\pipe\\(?P<p>[A-Za-z0-9_\-]+)", re.IGNORECASE)
_SV_LINE = re.compile(r"\bmsrpc\b[ \t]+(?P<v>[A-Za-z].+?)\s*$", re.MULTILINE)


def parse_rpcdump(text: str) -> list[MsrpcFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    endpoints = len(_UUID.findall(text))
    pipes = sorted({m.group("p") for m in _PIPE.finditer(text)})
    if endpoints == 0 and not pipes:
        return []
    findings = [MsrpcFinding("access", "unauth", "RPC endpoint mapper answered without auth")]
    if endpoints:
        findings.append(MsrpcFinding("endpoints", str(endpoints), "RPC interfaces mapped"))
    for pipe in pipes:
        findings.append(MsrpcFinding("pipe", pipe, "named pipe (RPC binding)"))
    return findings


def parse_msrpc_nmap(text: str) -> list[MsrpcFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    findings: list[MsrpcFinding] = []
    pipes = sorted({m.group("p") for m in _PIPE.finditer(text)})
    for pipe in pipes:
        findings.append(MsrpcFinding("pipe", pipe, "named pipe (RPC binding)"))
    sv = _SV_LINE.search(text)
    if sv is not None and sv.group("v").strip():
        findings.append(MsrpcFinding("version", sv.group("v").strip(), "MSRPC banner"))
    return findings


_PARSERS = {"msrpc-rpcdump": parse_rpcdump, "msrpc-nmap": parse_msrpc_nmap}


def parse_msrpc_tool(tool: str, text: str) -> list[MsrpcFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
