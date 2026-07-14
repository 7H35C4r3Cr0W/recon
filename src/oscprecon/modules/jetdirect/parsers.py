from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class JetdirectFinding:
    kind: str  # product | version
    value: str
    detail: str = ""
    module: str = "jetdirect"

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
# the -sV line names the product after the 9100 service, e.g.
# "9100/tcp open  jetdirect  HP LaserJet 4250 firmware 20140217".
_SV_LINE = re.compile(
    r"^\d+/tcp\s+open\s+(?:jetdirect|pdl-datastream|hp-pdl-datastr)\s+(?P<v>.+?)\s*$",
    re.MULTILINE | re.IGNORECASE,
)
_FIRMWARE = re.compile(r"\bfirmware\s+(?P<v>[\w.\-]+)", re.IGNORECASE)


def parse_jetdirect_info(text: str) -> list[JetdirectFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    match = _SV_LINE.search(text)
    if match is None:
        return []
    product = match.group("v").strip()
    findings = [JetdirectFinding("product", product, "printer model (9100 banner)")]
    firmware = _FIRMWARE.search(product)
    if firmware is not None:
        findings.append(JetdirectFinding("version", firmware.group("v"), "printer firmware"))
    return findings


_PARSERS = {"jetdirect-info": parse_jetdirect_info}


def parse_jetdirect_tool(tool: str, text: str) -> list[JetdirectFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
