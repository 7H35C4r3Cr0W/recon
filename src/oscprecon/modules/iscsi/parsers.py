from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class IscsiFinding:
    kind: str  # access | target
    value: str
    detail: str = ""
    module: str = "iscsi"

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
# an iSCSI Qualified Name, e.g. "iqn.2004-04.com.example:storage.disk1".
_IQN = re.compile(r"iqn\.\d{4}-\d{2}\.[A-Za-z0-9.\-]+(?::[A-Za-z0-9.:_\-]+)?")


def parse_iscsi_targets(text: str) -> list[IscsiFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    iqns = []
    seen: set[str] = set()
    for match in _IQN.finditer(text):
        iqn = match.group(0)
        if iqn not in seen:
            seen.add(iqn)
            iqns.append(iqn)
    if not iqns:
        return []
    findings = [IscsiFinding("access", "discovery-open", "SendTargets discovery answered")]
    findings.extend(IscsiFinding("target", iqn, "exported iSCSI target") for iqn in iqns)
    return findings


_PARSERS = {"iscsi-discovery": parse_iscsi_targets, "iscsi-nmap": parse_iscsi_targets}


def parse_iscsi_tool(tool: str, text: str) -> list[IscsiFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
