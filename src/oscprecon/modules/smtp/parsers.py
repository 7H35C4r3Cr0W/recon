from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

# ESMTP verbs worth surfacing: VRFY/EXPN enable user enumeration; the rest shape follow-ups.
_NOTABLE_VERBS = ("VRFY", "EXPN", "ETRN", "TURN", "STARTTLS", "AUTH")
# smtp-ntlm-info leaks AD domain/host names from an NTLM challenge — high-value recon.
_NTLM_KEYS = (
    "Target_Name",
    "NetBIOS_Domain_Name",
    "NetBIOS_Computer_Name",
    "DNS_Domain_Name",
    "DNS_Computer_Name",
    "DNS_Tree_Name",
    "Product_Version",
)


@dataclass
class SmtpFinding:
    kind: str  # banner | verb | open-relay | ntlm | note
    value: str
    detail: str = ""
    module: str = "smtp"

    def to_dict(self, discovered_at: str) -> dict[str, Any]:
        return {
            "module": self.module,
            "kind": self.kind,
            "value": self.value,
            "detail": self.detail,
            "discovered_at": discovered_at,
        }


# -sV prints the TLS-wrapped service as `ssl/smtp` (465) and 587 sometimes as `submission` — the
# module triggers on those ports/services, so the banner regex must accept them too.
_SMTP_VER = re.compile(
    r"^\d+/tcp[^\S\n]+open[^\S\n]+(?:ssl/)?(?:smtp[-\w]*|submission)[^\S\n]+(?P<ver>\S.*)$",
    re.MULTILINE,
)
# smtp-commands.nse returns TWO payloads — the EHLO extensions AND the HELP response — on two lines.
# VRFY/EXPN are base SMTP verbs that often surface ONLY on the HELP line, so read both.
_VERB_LINE_PREFIXES = ("smtp-commands:", "this server supports the following commands:")


def _verbs(text: str) -> list[SmtpFinding]:
    findings: list[SmtpFinding] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        line = re.sub(r"^\|[_ ]?", "", raw).strip()  # strip nmap's "| "/"|_" prefix
        low = line.lower()
        prefix = next((p for p in _VERB_LINE_PREFIXES if low.startswith(p)), None)
        if prefix is None:
            continue
        payload = line[len(prefix) :]
        tokens = {t.upper() for t in re.split(r"[,\s]+", payload) if t}
        for verb in _NOTABLE_VERBS:
            if verb in tokens and verb not in seen:
                seen.add(verb)
                findings.append(SmtpFinding("verb", verb))
    return findings


def parse_nmap_smtp(text: str) -> list[SmtpFinding]:
    findings: list[SmtpFinding] = []
    version = _SMTP_VER.search(text)
    if version is not None:
        findings.append(SmtpFinding("banner", version.group("ver").strip()))
    findings.extend(_verbs(text))
    lower = text.lower()
    if "is an open relay" in lower:
        findings.append(SmtpFinding("open-relay", "allowed", "server accepted relay tests"))
    elif "open relay" in lower:  # "... doesn't seem to be an open relay ..."
        findings.append(SmtpFinding("open-relay", "denied", ""))
    for key in _NTLM_KEYS:
        match = re.search(rf"{re.escape(key)}:\s*(?P<v>\S.*?)\s*$", text, re.MULTILINE)
        if match is not None:
            findings.append(SmtpFinding("ntlm", f"{key}: {match.group('v').strip()}"))
    return findings


_PARSERS = {"nmap-smtp": parse_nmap_smtp}


def parse_smtp_tool(tool: str, text: str) -> list[SmtpFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
