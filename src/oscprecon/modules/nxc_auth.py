from __future__ import annotations

import re

# netexec's login verdict, in one place.
#
# Every netexec protocol handler answers the one question a credential makes askable — "does this
# account actually work here?" — with the same three shapes:
#
#   WINRM  10.10.10.5  5985  DC01  [+] corp.local\svc:Passw0rd (Pwn3d!)
#   MSSQL  10.10.10.5  1433  DC01  [-] corp.local\svc:Passw0rd (STATUS_LOGON_FAILURE)
#   RDP    10.10.10.5  3389  DC01  [-] corp.local\svc:Passw0rd (STATUS_ACCOUNT_LOCKED_OUT)
#
# `(Pwn3d!)` means administrative access — on WinRM that is a shell, the single most useful thing
# recon can tell you after finding a password. Each service's parsers.py adapts this to its own
# Finding type; the recognition lives here so three copies can't drift.

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_SENTINEL = ("[missing]", "[blocked]")
_VERDICT = re.compile(
    r"^(?P<proto>[A-Z0-9]+)\s+\S+\s+\d+\s+\S+\s+\[(?P<sign>[+-])\]\s*(?P<who>.+?)\s*$"
)
# the secret is echoed back by netexec; §6 says show it, but a finding VALUE is a label — keep the
# identity there and let the raw output carry the rest.
_WHO = re.compile(r"^(?:(?P<domain>[^\\/]+)[\\/])?(?P<user>[^:]+):(?P<rest>.*)$")


def parse_login_verdict(text: str) -> list[tuple[str, str, str]]:
    """[(kind, value, detail)] — `auth` for a working credential, `auth-denied` for a refusal."""
    text = _ANSI.sub("", text)
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    out: list[tuple[str, str, str]] = []
    for line in text.splitlines():
        match = _VERDICT.match(line.rstrip())
        if match is None:
            continue
        who = match.group("who")
        identity = _WHO.match(who)
        if identity is None:
            continue
        user = identity.group("user").strip()
        domain = (identity.group("domain") or "").strip()
        label = f"{domain}\\{user}" if domain else user
        rest = identity.group("rest")
        admin = "pwn3d" in rest.lower()
        if match.group("sign") == "+":
            detail = "administrative access (Pwn3d!)" if admin else "credential accepted"
            out.append(("auth", label, detail))
        else:
            reason = rest.partition("(")[2].rstrip(")").strip() or "rejected"
            out.append(("auth-denied", label, reason))
    return out
