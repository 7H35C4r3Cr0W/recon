from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class SmbEntry:
    name: str
    is_dir: bool
    size: int = 0


# smbclient `ls`: "  <name>  <attrs>  <size>  <DOW> <Mon> <DD> <HH:MM:SS> <YYYY>". Anchor on the
# trailing date so a name with spaces survives; attrs is a letter combo (D=dir, A/N/H/R/S/L).
_SMB_LS = re.compile(
    r"^\s+(?P<name>.*\S)\s+(?P<attrs>[DAHRSNL]+)\s+(?P<size>\d+)\s+"
    r"\w{3}\s+\w{3}\s+\d+\s+[\d:]+\s+\d{4}\s*$"
)
# lines smbclient interleaves with a streamed file's content (`get file -`), plus its banners. Match
# each shape TIGHTLY, not a bare `Domain=`/`OS=`/`NT_STATUS` prefix: a peeked config file whose own
# content starts with `Domain=EXAMPLE`, `OS=Linux`, or `NT_STATUS...` was being silently dropped
# (bug #11). The connection banner is the full `Domain=[..] OS=[..] Server=[..]` line; NT_STATUS
# chatter is an uppercase error CODE; the ls footer is `<n> blocks of size <n>`.
_SMB_NOISE = re.compile(
    r'^(?:getting file |Try "help|\s*\d+ blocks of size \d+|NT_STATUS_[A-Z_]+\b)'
    r"|^Domain=\[[^\]]*\] OS=\[[^\]]*\] Server=\["
)


def parse_smbclient_ls(text: str) -> list[SmbEntry]:
    entries: list[SmbEntry] = []
    for line in text.splitlines():
        match = _SMB_LS.match(line.rstrip())
        if match is None:
            continue
        name = match.group("name").strip()
        if name in (".", ".."):
            continue
        is_dir = "D" in match.group("attrs")
        entries.append(SmbEntry(name, is_dir, 0 if is_dir else int(match.group("size"))))
    return entries


def strip_smbclient_noise(text: str) -> str:
    # drop smbclient's status/banner lines so a peek shows the FILE, not the tool chatter
    return "\n".join(line for line in text.splitlines() if not _SMB_NOISE.match(line))


@dataclass
class SmbFinding:
    kind: str  # auth | signing | share | user | group | policy | os | hostname | domain
    #          # | dialect | algo-weak | note | peek
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
    perm_start = perm_end = -1  # header column offsets of the Permissions cell (fixed-width table)
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
            # capture the fixed-width Permissions column span so an EMPTY perms cell can't pull the
            # Remark text ("READ" as a bare remark) in as a fake permission (share-perms bug #45).
            perm_start = rest.index("Permissions")
            perm_end = rest.index("Remark") if "Remark" in rest else len(rest)
            continue
        if rest.startswith("---"):
            continue
        if in_table:
            if rest.startswith("["):
                in_table = False
                continue
            # netexec pads columns, so split on 2+ spaces: a multi-word share name (single spaces)
            # stays intact.
            cols = re.split(r"\s{2,}", rest.strip())
            if not cols or not cols[0]:
                in_table = False
                continue
            # read perms ONLY from the Permissions column span (not every column after the name), so
            # a Remark where perms would be won't false-flag the share readable/writable. If a long
            # share name overflows the column, fall back to the old comma-token scan of cols[1].
            if perm_start >= 0 and len(cols[0]) <= perm_start:
                cell = rest[perm_start:perm_end]
            else:
                cell = cols[1] if len(cols) >= 2 else ""
            perms = [p for p in re.split(r"[,\s]+", cell.strip()) if p in ("READ", "WRITE")]
            findings.append(SmbFinding("share", cols[0], ",".join(perms)))
    return findings


_DOMAIN_USER = re.compile(r"^[^\\\s]+\\(?P<user>\S+)")


def parse_netexec_users(text: str) -> list[SmbFinding]:
    # netexec 1.4.0 prints --users as a fixed-width table with NO domain prefix and a
    # "-Username- -Last PW Set- -BadPW- -Description-" header; the username is the first column.
    # Older CME-style "DOMAIN\\user" lines are still handled via the backslash fallback.
    findings: list[SmbFinding] = []
    for line in text.splitlines():
        rest = _nxc_rest(line)
        if rest is None:
            continue
        rest = rest.strip()
        if not rest or rest.startswith("[") or rest.startswith("-Username-"):
            continue
        match = _DOMAIN_USER.match(rest)
        if match is not None:
            findings.append(SmbFinding("user", match.group("user")))
            continue
        findings.append(SmbFinding("user", rest.split()[0]))
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


# smbclient -L share row: "<name>  <Type>  [comment]" where Type is Disk/IPC/Printer. Its trailing
# status prose ("Reconnecting with SMB1 ...", "Unable to connect ...") has no Type column, so it
# must not be mistaken for a share name when smbclient omits the usual blank line before it.
_SHARE_TYPES = {"Disk", "IPC", "Printer", "Device"}


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
            cols = re.split(r"\s{2,}", stripped)  # 2+ spaces: keep multi-word share names intact
            if len(cols) >= 2 and cols[1] in _SHARE_TYPES and cols[0]:
                findings.append(SmbFinding("share", cols[0]))
    return findings


_RPC_USER = re.compile(r"user:\[(?P<name>[^\]]+)\]")


def parse_rpcclient_users(text: str) -> list[SmbFinding]:
    findings: list[SmbFinding] = []
    for line in text.splitlines():
        match = _RPC_USER.search(line)
        if match is not None:
            findings.append(SmbFinding("user", match.group("name")))
    return findings


# enum4linux-ng: the single richest source on an SMB box. Its output is colourised, sectioned, and
# shape-shifts with the version and with what the target allows — so parse it line-wise and tolerate
# every section being absent. Layout: banner lines carry a `[+]/[-]/[*]/[H]` marker and may open a
# multi-line YAML-ish block (users, groups, shares, policy) whose members are the following
# unmarked lines; a marker, a blank line, or a `=== section ===` banner closes the block.
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_E4L_MARKER = re.compile(r"^\[[+\-*H!]\]\s*")
_E4L_SECTION = re.compile(r"^\s*[=|]")
_E4L_KV = re.compile(r"^(?P<key>[^:]+):\s*(?P<value>.*)$")
_E4L_RID = re.compile(r"^'?(?P<rid>\d+)'?:\s*$")
_E4L_SHARE_NAME = re.compile(r"^(?P<name>[^\s:][^:]*):\s*$")
_E4L_DIALECT = re.compile(r"^\s+(?P<name>SMB \d[\d.]*):\s*(?P<enabled>true|false)\s*$", re.I)
_E4L_SIGNING = re.compile(r"^SMB signing required:\s*(?P<required>\S+)", re.I)
_E4L_AUTH = re.compile(r"allows authentication via username '(?P<user>[^']*)' and password")
_E4L_MAPPING = re.compile(r"^Mapping:\s*(?P<mapping>\w+),\s*Listing:\s*(?P<listing>.+)$", re.I)

_E4L_BLOCKS = (
    ("users", re.compile(r"user\(s\).*:$")),
    ("groups", re.compile(r"group\(s\).*:$")),
    ("shares", re.compile(r"share\(s\).*:$")),
    ("policy", re.compile(r"^Found policy:$")),
    ("dialects", re.compile(r"^Supported dialects:$")),
)
# identity keys worth a finding, and the wording that tells the operator which one it is
_E4L_IDENTITY = {
    "got domain/workgroup name": ("domain", "netbios workgroup/domain"),
    "domain": ("domain", "domain via RPC"),
    "netbios domain name": ("domain", "netbios domain"),
    "dns domain": ("domain", "dns domain"),
    "netbios computer name": ("hostname", "netbios computer name"),
    "fqdn": ("hostname", "fqdn"),
}
_E4L_OS_KEYS = ("os", "os version", "os build")
_E4L_POLICY_KEYS = frozenset(
    {
        "minimum password length",
        "password history length",
        "maximum password age",
        "lockout threshold",
        "account lockout threshold",
    }
)
# enum4linux says "Lockout threshold", netexec says "Account Lockout Threshold" — one policy, two
# spellings. Normalise so the summary doesn't list it twice with two number formats. [review]
_E4L_POLICY_ALIASES = {"account lockout threshold": "Lockout threshold"}
_E4L_EMPTY = frozenset({"", "null", "none", "n/a", "unknown", "not supported"})


def _e4l_value(raw: str) -> str:
    value = raw.strip().strip("'\"").strip()
    return "" if value.lower() in _E4L_EMPTY else value


def _e4l_block(body: str) -> str:
    for name, pattern in _E4L_BLOCKS:
        if pattern.search(body):
            return name
    return ""


def parse_enum4linux(text: str) -> list[SmbFinding]:
    findings: list[SmbFinding] = []
    shares: dict[str, SmbFinding] = {}
    os_info: dict[str, str] = {}
    dialects: list[str] = []
    smb1 = False
    block = ""
    check = ""
    tested_share = ""
    rid = ""
    last_user: SmbFinding | None = None

    for raw in _ANSI.sub("", text).splitlines():
        line = raw.rstrip()
        if not line.strip() or _E4L_SECTION.match(line):
            block = ""
            continue
        body = _E4L_MARKER.sub("", line)
        is_marker = body != line
        stripped = body.strip()
        entry = _e4l_block(stripped)
        if entry:
            # the header line only opens the block — its own text ("Found 4 share(s):") is not a
            # member of it
            block = entry
            rid = ""
            continue
        if is_marker:
            block = ""
            if "Testing share" in stripped:
                tested_share = stripped.split("Testing share", 1)[1].strip()
            elif "Check for anonymous access" in stripped:
                check = "null"
            elif "Check for guest access" in stripped:
                check = "guest"

        auth = _E4L_AUTH.search(stripped)
        if auth is not None:
            user = auth.group("user")
            if check == "guest" and user:
                findings.append(
                    SmbFinding(
                        "auth",
                        "guest session",
                        f"random username '{user}' accepted — guest/anonymous mapping",
                    )
                )
            else:
                findings.append(
                    SmbFinding("auth", "null session", "anonymous SMB session accepted")
                )
            continue
        signing = _E4L_SIGNING.match(stripped)
        if signing is not None:
            required = signing.group("required").lower() == "true"
            findings.append(
                SmbFinding(
                    "signing",
                    "enabled" if required else "disabled",
                    "required" if required else "signing not required — relay candidate",
                )
            )
            continue
        mapping = _E4L_MAPPING.match(stripped)
        if mapping is not None and tested_share:
            share = shares.setdefault(tested_share, SmbFinding("share", tested_share))
            if mapping.group("listing").strip().upper() == "OK":
                share.detail = "READ"
            continue

        if block == "dialects":
            dialect = _E4L_DIALECT.match(body)
            if dialect is not None and dialect.group("enabled").lower() == "true":
                name = dialect.group("name")
                dialects.append(name)
                smb1 = smb1 or name.upper().startswith("SMB 1")
            continue
        if block == "shares":
            share_name = _E4L_SHARE_NAME.match(body)
            if share_name is not None:
                name = share_name.group("name")
                shares.setdefault(name, SmbFinding("share", name))
            continue

        indented = body[:1].isspace()
        if block in ("users", "groups"):
            rid_match = _E4L_RID.match(body)
            if rid_match is not None:
                rid = rid_match.group("rid")
                continue
            kv = _E4L_KV.match(body)
            if kv is None or not indented:
                continue
            key = kv.group("key").strip().lower()
            value = _e4l_value(kv.group("value"))
            if not value:
                continue
            if key == "username":
                last_user = SmbFinding("user", value, f"rid {rid}" if rid else "")
                findings.append(last_user)
            elif key == "groupname":
                findings.append(SmbFinding("group", value, f"rid {rid}" if rid else ""))
            elif key == "name" and last_user is not None:
                last_user.detail = ", ".join(p for p in (last_user.detail, value) if p)
            continue

        kv = _E4L_KV.match(stripped)
        if kv is None:
            continue
        key = kv.group("key").strip().lower()
        value = _e4l_value(kv.group("value"))
        if block == "policy" and indented and key in _E4L_POLICY_KEYS:
            # keep the tool's own casing, but collapse the two spellings of one policy
            display = _E4L_POLICY_ALIASES.get(key, kv.group("key").strip())
            findings.append(SmbFinding("policy", display, kv.group("value").strip()))
            continue
        if not value:
            continue
        if key in _E4L_OS_KEYS:
            os_info.setdefault(key, value)
        elif key in _E4L_IDENTITY:
            kind, detail = _E4L_IDENTITY[key]
            findings.append(SmbFinding(kind, value, detail))

    if "os" in os_info:
        detail = ", ".join(
            f"{label} {os_info[k]}"
            for label, k in (("version", "os version"), ("build", "os build"))
            if k in os_info
        )
        findings.append(SmbFinding("os", os_info["os"], detail))
    if dialects:
        findings.append(SmbFinding("dialect", ", ".join(dialects), "supported dialects"))
    if smb1:
        # why: SMBv1 reachable is the MS17-010/EternalBlue precondition — the one dialect fact an
        # operator acts on. 'algo-weak' is the existing weak-posture kind (finding_severity), so it
        # surfaces without inventing a severity.
        findings.append(
            SmbFinding(
                "algo-weak",
                "SMBv1 enabled",
                "legacy dialect — MS17-010 / EternalBlue precondition; "
                "confirm with nmap --script smb-vuln-ms17-010",
            )
        )
    findings.extend(shares.values())
    return _dedup_findings(findings)


def _dedup_findings(findings: list[SmbFinding]) -> list[SmbFinding]:
    # the same fact is reported by several enum methods (SMB session + RPC + merged summary)
    seen: set[tuple[str, str]] = set()
    unique: list[SmbFinding] = []
    for f in findings:
        key = (f.kind, f.value.lower())
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    return unique


_PARSERS = {
    "enum4linux": parse_enum4linux,
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


def writable_shares(findings: list[SmbFinding]) -> list[str]:
    # a guest/anon-WRITABLE share is a real exposure (upload / print-job / wide-link write vector),
    # surfaced distinctly from a merely-readable one (HTB Abducted: guest-writable printer share).
    return [f.value for f in findings if f.kind == "share" and "WRITE" in f.detail]


def dedup_share_findings(findings: list[SmbFinding]) -> list[SmbFinding]:
    # the same share is listed by two enum methods — `smbclient -L` (name only, no perms) and
    # `netexec --shares` (name + READ/WRITE) — so a share otherwise appears twice, once blank and
    # once with its access. Collapse by name, unioning the access tokens so the WRITE/READ a single
    # method saw is never lost and the graph/report shows one node per share.
    access: dict[str, set[str]] = {}
    order: list[str] = []
    others: list[SmbFinding] = []
    for f in findings:
        if f.kind != "share":
            others.append(f)
            continue
        if f.value not in access:
            access[f.value] = set()
            order.append(f.value)
        access[f.value].update(t for t in re.split(r"[,\s]+", f.detail) if t in ("READ", "WRITE"))
    merged = [
        SmbFinding("share", name, ",".join(t for t in ("READ", "WRITE") if t in access[name]))
        for name in order
    ]
    return others + merged
